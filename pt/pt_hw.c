#include <linux/module.h>
#include <linux/init.h>
#include <linux/cpu.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/percpu.h>
#include <linux/mm.h>
#include <linux/errno.h>

#include <asm/cpufeature.h>
#include <asm/msr.h>
#include <asm/msr-index.h>

#include "pt_log.h"
#include "pt_hw.h"

/* 2MB buffer per CPU */
#define PT_BUF_ORDER 9
#define PT_BUF_SIZE (1ULL << (12 + PT_BUF_ORDER))

/* Global exported symbols for vmcore analysis */
struct pt_cpu_meta *pt_meta;
EXPORT_SYMBOL(pt_meta);

int num_cpus;
EXPORT_SYMBOL(num_cpus);

static struct page **pt_pages;

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

    num_cpus = num_online_cpus();

    pt_meta = kcalloc(num_cpus, sizeof(*pt_meta), GFP_KERNEL);
    if (!pt_meta)
        return -ENOMEM;

    pt_pages = kcalloc(num_cpus, sizeof(*pt_pages), GFP_KERNEL);
    if (!pt_pages) {
        kfree(pt_meta);
        pt_meta = NULL;
        return -ENOMEM;
    }

    /* Allocate 2MB per-CPU buffers */
    for_each_online_cpu(cpu) {
        int nid = cpu_to_node(cpu);

        pt_pages[cpu] = alloc_pages_node(nid, GFP_KERNEL | __GFP_ZERO, PT_BUF_ORDER);
        if (!pt_pages[cpu]) {
            pt_err("Buffer alloc failed for CPU%d\n", cpu);
            ret = -ENOMEM;
            goto fail;
        }

        /* Basic metadata info */
        pt_meta[cpu].cpu = cpu;
        pt_meta[cpu].buf_size = PT_BUF_SIZE;
    }

    return 0;

fail:
    /* Free only those CPUs which allocated */
    for_each_online_cpu(cpu) {
        if (pt_pages[cpu]) {
            free_pages((unsigned long)page_address(pt_pages[cpu]), PT_BUF_ORDER);
            pt_pages[cpu] = NULL;
        }
    }

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

    for_each_online_cpu(cpu) {
        if (pt_pages[cpu])
            free_pages((unsigned long)page_address(pt_pages[cpu]), PT_BUF_ORDER);
    }

    kfree(pt_pages);
    pt_pages = NULL;

    kfree(pt_meta);
    pt_meta = NULL;
}

void pt_start_cpu(void *info)
{
    u64 val;
    int cpu = smp_processor_id();

    phys_addr_t paddr = ((phys_addr_t)page_to_pfn(pt_pages[cpu]) << PAGE_SHIFT);

    pt_meta[cpu].buf_phys = paddr;

    /* Program output base */
    wrmsrl(MSR_IA32_RTIT_OUTPUT_BASE, paddr);

    wrmsrl(MSR_IA32_RTIT_OUTPUT_MASK, PT_BUF_SIZE - 1);

    /* OS=1, enable kernel tracing */
    val = RTIT_CTL_OS;
    wrmsrl(MSR_IA32_RTIT_CTL, val);

    val |= RTIT_CTL_TRACEEN;
    wrmsrl(MSR_IA32_RTIT_CTL, val);
}

void pt_stop_cpu(void *info)
{
    u64 ctl;

    rdmsrl(MSR_IA32_RTIT_CTL, ctl);
    ctl &= ~RTIT_CTL_TRACEEN;
    wrmsrl(MSR_IA32_RTIT_CTL, ctl);
}

/* Save PT state for vmcore analysis */
void pt_snapshot_cpu(void *info)
{
    int cpu = smp_processor_id();

    rdmsrl(MSR_IA32_RTIT_CTL, pt_meta[cpu].msr_ctl);
    rdmsrl(MSR_IA32_RTIT_STATUS, pt_meta[cpu].msr_status);
    rdmsrl(MSR_IA32_RTIT_OUTPUT_MASK, pt_meta[cpu].msr_output_mask);
}

/* Panic notifier */
int pt_panic_handler(struct notifier_block *nb, unsigned long event, void *unused)
{
    /* 1. Stop tracing */
    on_each_cpu(pt_stop_cpu, NULL, 1);

    /* 2. Snapshot MSRs */
    on_each_cpu(pt_snapshot_cpu, NULL, 1);

    return NOTIFY_DONE;
}
