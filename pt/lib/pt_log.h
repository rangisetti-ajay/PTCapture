#ifndef _PT_LOG_H
#define _PT_LOG_H

#include <linux/printk.h>

#define pt_info(fmt, ...) pr_info("pt_capture: " fmt, ##__VA_ARGS__)
#define pt_err(fmt, ...)  pr_err("pt_capture: " fmt, ##__VA_ARGS__)

#endif