#include <linux/module.h>
#include <linux/init.h>
#include <linux/cpu.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/percpu.h>
#include <linux/mm.h>
#include <linux/errno.h>
#include <linux/cpumask.h>
#include <linux/types.h>

#include <asm/cpufeature.h>
#include <asm/msr.h>
#include <asm/msr-index.h>

#include "pt_log.h"
#include "pt_hw.h"



/*
 * Some kernels (like your 4.18 el8) only define MSR_IA32_RTIT_OUTPUT_MASK.
 * Newer ones use MSR_IA32_RTIT_OUTPUT_MASK_PTRS.
 * Make them equivalent for our single-range use.
 */
#ifndef MSR_IA32_RTIT_OUTPUT_MASK_PTRS
#define MSR_IA32_RTIT_OUTPUT_MASK_PTRS MSR_IA32_RTIT_OUTPUT_MASK
#endif

/* 2MB buffer per CPU */
#define PT_BUF_ORDER 9
#define PT_BUF_SIZE  (1ULL << (12 + PT_BUF_ORDER))

/* ToPA table is a single page */
#define PT_TOPA_ORDER 0
#define PT_TOPA_SIZE  PAGE_SIZE

/* ToPA entry encoding (matches Linux perf driver / SDM usage model) */
#define TOPA_SHIFT      12
#define TOPA_END        BIT_ULL(0)
#define TOPA_INT        BIT_ULL(2)
#define TOPA_STOP       BIT_ULL(4)
#define TOPA_SIZE_SHIFT 6

/* Global exported symbols for vmcore analysis */
struct pt_cpu_meta *pt_meta;
EXPORT_SYMBOL(pt_meta);

/*
 * num_cpus: number of CPU slots (nr_cpu_ids), so pt_meta[cpu] is always safe
 * for any cpu < num_cpus.
 */
int num_cpus;
EXPORT_SYMBOL(num_cpus);

/* Internal: per-CPU pages backing the PT buffers */
static struct page **pt_pages;

/* Internal: per-CPU pages backing ToPA tables */
static struct page **pt_topa_pages;

static bool pt_has_intel_pt(void)
{
    return boot_cpu_has(X86_FEATURE_INTEL_PT);
}

int pt_chkhw_support(void)
{
    if (!pt_has_intel_pt()) {
        pt_err("CPU does not support Intel PT\n");
        return -ENODEV;
    }
    return 0;
}

int pt_allocbuffs(void)
{
    int cpu, ret = 0;

    /*
     * Allocate for all possible CPU IDs so we can index by cpu directly
     * without out-of-bounds if IDs are sparse.
     */
    num_cpus = nr_cpu_ids;

    pt_meta = kcalloc(num_cpus, sizeof(*pt_meta), GFP_KERNEL);
    if (!pt_meta)
        return -ENOMEM;

    pt_pages = kcalloc(num_cpus, sizeof(*pt_pages), GFP_KERNEL);
    if (!pt_pages) {
        kfree(pt_meta);
        pt_meta = NULL;
        return -ENOMEM;
    }

    pt_topa_pages = kcalloc(num_cpus, sizeof(*pt_topa_pages), GFP_KERNEL);
    if (!pt_topa_pages) {
        kfree(pt_pages);       
        pt_pages = NULL;
        kfree(pt_meta);
        pt_meta = NULL;
        return -ENOMEM;
    }

    /* Allocate 2MB per-CPU buffers for each online CPU at init time */
    for_each_online_cpu(cpu) {
        int nid = cpu_to_node(cpu);
        struct page *pg;
        struct page *tp;

        pg = alloc_pages_node(nid, GFP_KERNEL | __GFP_ZERO, PT_BUF_ORDER);
        if (!pg) {
            pt_err("Buffer alloc failed for CPU%d\n", cpu);
            ret = -ENOMEM;
            goto fail;
        }

        tp = alloc_pages_node(nid, GFP_KERNEL | __GFP_ZERO, PT_TOPA_ORDER);
        if (!tp) {
            pt_err("ToPA alloc failed for CPU%d\n", cpu);
            __free_pages(pg, PT_BUF_ORDER);
            ret = -ENOMEM;
            goto fail;
        }

        pt_pages[cpu] = pg;
        pt_topa_pages[cpu] = tp; 

        pt_meta[cpu].cpu      = cpu;
        pt_meta[cpu].buf_size = PT_BUF_SIZE;
        pt_meta[cpu].buf_phys =
            ((phys_addr_t)page_to_pfn(pg) << PAGE_SHIFT);

        pt_meta[cpu].topa_phys =
            ((phys_addr_t)page_to_pfn(tp) << PAGE_SHIFT);
    }

    return 0;

fail:
    /* Free any buffers we successfully allocated */
    for (cpu = 0; cpu < num_cpus; cpu++) {
        if (pt_pages[cpu]) {
            free_pages((unsigned long)page_address(pt_pages[cpu]),
                       PT_BUF_ORDER);
            pt_pages[cpu] = NULL;
        }
        if (pt_pages[cpu])
            __free_pages(pt_pages[cpu], PT_BUF_ORDER);
        if (pt_topa_pages && pt_topa_pages[cpu])
            __free_pages(pt_topa_pages[cpu], PT_TOPA_ORDER);
        pt_pages[cpu] = NULL;
        if (pt_topa_pages)
            pt_topa_pages[cpu] = NULL;

    }
    kfree(pt_topa_pages);
    pt_topa_pages = NULL;

    kfree(pt_pages);
    pt_pages = NULL;

    kfree(pt_meta);
    pt_meta = NULL;

    return ret;
}

void pt_freebuffs(void)
{
    int cpu;

    if (!pt_pages)
        return;

    for (cpu = 0; cpu < num_cpus; cpu++) {
        if (pt_pages[cpu])
            free_pages((unsigned long)page_address(pt_pages[cpu]),
                       PT_BUF_ORDER);

        if (pt_pages[cpu])
            __free_pages(pt_pages[cpu], PT_BUF_ORDER);
        if (pt_topa_pages && pt_topa_pages[cpu])
            __free_pages(pt_topa_pages[cpu], PT_TOPA_ORDER);
    }

    kfree(pt_pages);
    pt_pages = NULL;

    kfree(pt_topa_pages);
    pt_topa_pages = NULL;

    kfree(pt_meta);
    pt_meta = NULL;
}

static inline u64 pt_build_topa_entry(phys_addr_t phys, u8 order, u64 flags)
{
    /*
     * Base must be 4K-aligned. Raw format uses base in bits 63:12, so we can
     * OR the aligned phys with flag/size bits in the low 12 bits.
     *
     * Linux perf sets entry->base = phys >> TOPA_SHIFT and entry->size = order. :contentReference[oaicite:4]{index=4}
     */
    u64 e = (u64)phys & ~((1ULL << TOPA_SHIFT) - 1);
    e |= ((u64)order << TOPA_SIZE_SHIFT);
    e |= flags;
    return e;
}



/*
 * Start PT on the current CPU.
 * Called via on_each_cpu() from pt_main.c:enabled_write().
 */
void pt_start_cpu(void *info)
{
    u64 ctl_req, ctl_hw, status, mask;
    int cpu = smp_processor_id();
    struct page *pg;
    struct page *tp;
    phys_addr_t paddr;
    phys_addr_t topa_phys;
    u64 *topa;

    if (!pt_pages || !pt_topa_pages || !pt_meta || cpu >= num_cpus) {
        pt_err("pt_start_cpu: invalid cpu=%d or pt_pages/pt_meta=NULL\n",
               cpu);
        return;
    }

    pg = pt_pages[cpu];
    tp = pt_topa_pages[cpu];
    if (!pg) {
        pt_err("pt_start_cpu: no buffer allocated for cpu=%d\n", cpu);
        return;
    }
    if (!tp) {
        pt_err("pt_start_cpu: no ToPA table allocated for cpu=%d\n", cpu);
        return;
    }

    paddr = ((phys_addr_t)page_to_pfn(pg) << PAGE_SHIFT);
    topa_phys = ((phys_addr_t)page_to_pfn(tp) << PAGE_SHIFT);

    pt_meta[cpu].cpu      = cpu;
    pt_meta[cpu].buf_phys = paddr;
    pt_meta[cpu].buf_size = PT_BUF_SIZE;
    pt_meta[cpu].topa_phys = topa_phys;

    if (pt_meta[cpu].buf_phys & (PT_BUF_SIZE - 1)) {
        pt_err("cpu%d: PT buffer phys not aligned to size! phys=0x%llx size=0x%llx\n", cpu,
           (u64)pt_meta[cpu].buf_phys, (u64)PT_BUF_SIZE);
        return;
    }
    

    /*
     * Program ToPA table (single-entry style):
+     *   entry[0] = our 2MB output region
+     *   entry[1] = END link that points back to the ToPA table itself
+     *
+     * The Linux Intel PT driver does exactly this when topa_multiple_entries=0. :contentReference[oaicite:5]{index=5}
+     */
    topa = (u64 *)page_address(tp);
    if (!topa) {
        pt_err("cpu%d: ToPA page_address() failed\n", cpu);
        return;
    }
    topa[0] = pt_build_topa_entry(paddr, PT_BUF_ORDER, 0 /* no STOP/INT */);
    topa[1] = pt_build_topa_entry(topa_phys, 0 /* size ignored */, TOPA_END);
    /* Make sure ToPA writes are visible before enabling tracing */
    wmb();

    /*
+     * Program ToPA output base + pointers format like perf:
+     *   OUTPUT_BASE = phys(ToPA table)
+     *   OUTPUT_MASK = 0x7f | (topa_idx<<7) | (output_off<<32)
+     * For start: idx=0, off=0 => 0x7f. :contentReference[oaicite:6]{index=6}
+     */
    wrmsrl(MSR_IA32_RTIT_OUTPUT_BASE, topa_phys);
    wrmsrl(MSR_IA32_RTIT_OUTPUT_MASK_PTRS, 0x7fULL);

    /*
     * Request: enable OS tracing + TRACEEN.
     * (You can OR in other RTIT_CTL_* bits later if desired.)
     */
    ctl_req = RTIT_CTL_OS | RTIT_CTL_TOPA | RTIT_CTL_BRANCH_EN | RTIT_CTL_TRACEEN;
    wrmsrl(MSR_IA32_RTIT_CTL, ctl_req);

    /* Read back what hardware actually kept */
    rdmsrl(MSR_IA32_RTIT_CTL, ctl_hw);
    rdmsrl(MSR_IA32_RTIT_STATUS,           status);
    rdmsrl(MSR_IA32_RTIT_OUTPUT_MASK_PTRS, mask);
    pt_meta[cpu].msr_output_base = topa_phys;

    /* Log for debugging */
    pt_info("cpu%d: requested IA32_RTIT_CTL=0x%016llx, hw=0x%016llx, STATUS=0x%016llx, MASK=0x%016llx\n",
            cpu,
            (unsigned long long)ctl_req,
            (unsigned long long)ctl_hw,
            (unsigned long long)status,
            (unsigned long long)mask);

    if (!(ctl_hw & RTIT_CTL_TRACEEN)) {
        pt_err("cpu%d: TRACEEN bit did not stick (hw CTL=0x%016llx) – PT is configured but not actually tracing\n",
               cpu, (unsigned long long)ctl_hw);
    }

    /* Snapshot MSRs for debugfs (cpumsrs) */
    pt_meta[cpu].msr_ctl         = ctl_hw;
    pt_meta[cpu].msr_status      = status;
    pt_meta[cpu].msr_output_mask = mask;
}


/*
 * Stop PT on the current CPU – clear TRACEEN and refresh snapshot.
 */
void pt_stop_cpu(void *info)
{
    u64 ctl, status, mask;
    int cpu = smp_processor_id();

    rdmsrl(MSR_IA32_RTIT_CTL, ctl);
    ctl &= ~RTIT_CTL_TRACEEN;
    wrmsrl(MSR_IA32_RTIT_CTL, ctl);

    /* Refresh snapshot for cpumsrs */
    rdmsrl(MSR_IA32_RTIT_CTL,               ctl);
    rdmsrl(MSR_IA32_RTIT_STATUS,            status);
    rdmsrl(MSR_IA32_RTIT_OUTPUT_MASK_PTRS,  mask);
    /* Also capture output base: points to ToPA table in ToPA mode */
    if (pt_meta && cpu < num_cpus)
        rdmsrl(MSR_IA32_RTIT_OUTPUT_BASE, pt_meta[cpu].msr_output_base);
 

    if (pt_meta && cpu < num_cpus) {
        pt_meta[cpu].msr_ctl         = ctl;
        pt_meta[cpu].msr_status      = status;
        pt_meta[cpu].msr_output_mask = mask;
    }
}

/*
 * Save PT state for vmcore analysis (called at panic via notifier).
 */
void pt_snapshot_cpu(void *info)
{
    int cpu = smp_processor_id();

    if (!pt_meta || cpu >= num_cpus)
        return;

    rdmsrl(MSR_IA32_RTIT_CTL,               pt_meta[cpu].msr_ctl);
    rdmsrl(MSR_IA32_RTIT_STATUS,            pt_meta[cpu].msr_status);
    rdmsrl(MSR_IA32_RTIT_OUTPUT_MASK_PTRS,  pt_meta[cpu].msr_output_mask);
    rdmsrl(MSR_IA32_RTIT_OUTPUT_BASE,       pt_meta[cpu].msr_output_base);
}

/*
 * Panic notifier – stop PT + snapshot MSRs.
 */
int pt_panic_handler(struct notifier_block *nb, unsigned long event, void *unused)
{
    /* 1. Stop tracing on all CPUs */
    on_each_cpu(pt_stop_cpu, NULL, 1);

    /* 2. Snapshot MSRs on all CPUs */
    on_each_cpu(pt_snapshot_cpu, NULL, 1);

    return NOTIFY_DONE;
}
