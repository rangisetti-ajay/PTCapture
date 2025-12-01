//#define pr_fmt(fmt) "pt_capture: " fmt

#include <linux/module.h>
#include <linux/init.h>
#include <linux/cpu.h>
#include <linux/debugfs.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/seq_file.h>
#include <linux/notifier.h>

#include "lib/pt_capture.h"

static struct dentry *debug_dir;
static struct dentry *debug_enabled;
static struct dentry *debug_cpumsrs;

static spinlock_t trace_lock;
static int tracing_enabled;

/* ---------- enabled debugfs file ---------- */

static ssize_t enabled_read(struct file *f, char __user *buf,
                            size_t cnt, loff_t *ppos)
{
    char kbuf[8];
    int len;
    int val;

    if (*ppos > 0)
        return 0;

    val = READ_ONCE(tracing_enabled);
    len = snprintf(kbuf, sizeof(kbuf), "%d\n", val);

    if (copy_to_user(buf, kbuf, len))
        return -EFAULT;

    *ppos = len;
    return len;
}

static ssize_t enabled_write(struct file *f, const char __user *buf,
                             size_t cnt, loff_t *ppos)
{
    char kbuf[16];
    long val;
    int ret;

    if (cnt >= sizeof(kbuf))
        return -EINVAL;

    if (copy_from_user(kbuf, buf, cnt))
        return -EFAULT;

    kbuf[cnt] = '\0';

    ret = kstrtol(kbuf, 0, &val);
    if (ret)
        return ret;

    /* Only accept 0 or 1 */
    if (val != 0 && val != 1)
        return -EINVAL;

    spin_lock(&trace_lock);

    if (val && !tracing_enabled) {
        on_each_cpu(pt_start_cpu, NULL, 1);
        WRITE_ONCE(tracing_enabled, 1);
        pt_info("Tracing enabled\n");

    } else if (!val && tracing_enabled) {
        on_each_cpu(pt_stop_cpu, NULL, 1);
        WRITE_ONCE(tracing_enabled, 0);
        pt_info("Tracing disabled\n");
    }

    spin_unlock(&trace_lock);
    return cnt;
}

static const struct file_operations enabled_fops = {
    .owner = THIS_MODULE,
    .read  = enabled_read,
    .write = enabled_write,
};

/* ---------- cpumsrs debugfs file ---------- */

static int cpumsrs_show(struct seq_file *m, void *v)
{
    int cpu;

    seq_puts(m,
         "CPU  DataPhys           Size      ToPAPhys           OUT_BASE           IA32_RTIT_CTL       STATUS              OUT_MASK_PTRS\n");

    for_each_online_cpu(cpu) {
        const struct pt_cpu_meta *meta = &pt_meta[cpu];

        seq_printf(m,
             "%3d  0x%016llx  %8llu  0x%016llx  0x%016llx  0x%016llx  0x%016llx  0x%016llx\n",
            meta->cpu,
            (unsigned long long)meta->buf_phys,
            meta->buf_size,
            (unsigned long long)meta->topa_phys,
            (unsigned long long)meta->msr_output_base,
            meta->msr_ctl,
            meta->msr_status,
            meta->msr_output_mask);
    }

    return 0;
}

static int cpumsrs_open(struct inode *inode, struct file *file)
{
    return single_open(file, cpumsrs_show, NULL);
}

static const struct file_operations cpumsrs_fops = {
    .owner   = THIS_MODULE,
    .open    = cpumsrs_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = single_release,
};

/* ---------- Panic notifier block ---------- */

static struct notifier_block pt_nb = {
    .notifier_call = pt_panic_handler,
    .priority      = INT_MAX,
};

/* ---------- Module init/exit ---------- */

static int __init pt_capture_init(void)
{
    int ret;

    pt_info("Loading PT Capture module...\n");

    ret = pt_chkhw_support();
    if (ret)
        return ret;

    ret = pt_allocbuffs();
    if (ret)
        return ret;

    spin_lock_init(&trace_lock);

    /* DebugFS */
    debug_dir = debugfs_create_dir("pt_capture", NULL);
    if (!debug_dir)
        return -ENOMEM;

    debug_enabled = debugfs_create_file("enabled", 0644, debug_dir,
                                        NULL, &enabled_fops);
    debug_cpumsrs = debugfs_create_file("cpumsrs", 0444, debug_dir,
                                        NULL, &cpumsrs_fops);

    if (!debug_enabled || !debug_cpumsrs)
        pt_info("pt_capture: some debugfs entries may be missing\n");

    /*
     * Register panic notifier. On your RHEL 9.6, panic_notifier_list
     * is available to modules; if it weren't, you'd see an unknown
     * symbol error at insmod time.
     */
    ret = atomic_notifier_chain_register(&panic_notifier_list, &pt_nb);
    if (ret)
        pt_err("Failed to register panic notifier: %d\n", ret);

    return 0;
}

static void __exit pt_capture_exit(void)
{
    pt_info("Unloading PT Capture...\n");

    /* Stop tracing if active */
    if (READ_ONCE(tracing_enabled))
        on_each_cpu(pt_stop_cpu, NULL, 1);

    atomic_notifier_chain_unregister(&panic_notifier_list, &pt_nb);

    debugfs_remove_recursive(debug_dir);

    pt_freebuffs();
}

module_init(pt_capture_init);
module_exit(pt_capture_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ajay Rangisetti");
MODULE_DESCRIPTION("Intel PT Crash Capture Module");

