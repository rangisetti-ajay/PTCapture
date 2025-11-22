
#ifndef _PT_HW_H
#define _PT_HW_H

#include <linux/notifier.h>
#include <linux/types.h>

struct pt_cpu_meta {
    u32 cpu;
    phys_addr_t buf_phys;
    u64 buf_size;

    /* Snapshot MSRs (captured on panic) */
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
