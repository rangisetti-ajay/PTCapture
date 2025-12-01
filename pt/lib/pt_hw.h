#ifndef _PT_HW_H
#define _PT_HW_H

#include <linux/notifier.h>
#include <linux/types.h>

struct pt_cpu_meta {
    int cpu;
    u64 buf_size;
    phys_addr_t buf_phys;

    /* NEW: ToPA table physical address (per CPU) */
    phys_addr_t topa_phys;

    /* NEW: snapshot of IA32_RTIT_OUTPUT_BASE */
    u64 msr_output_base;

    /* already existing fields (you had these) */
    u64 msr_ctl;
    u64 msr_status;
    u64 msr_output_mask;
};

extern struct pt_cpu_meta *pt_meta;
extern int num_cpus;

int pt_chkhw_support(void);
int pt_allocbuffs(void);
void pt_freebuffs(void);

void pt_start_cpu(void *info);
void pt_stop_cpu(void *info);

void pt_snapshot_cpu(void *info);
int pt_panic_handler(struct notifier_block *nb, unsigned long event, void *unused);

#endif

