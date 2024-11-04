#ifndef __COMMON_DEBUG_H__
#define __COMMON_DEBUG_H__

#define BPF_PRINTK( format, ... ) \
    { \
        static const char __fmt[] = format;                                 \
        bpf_trace_printk(__fmt, sizeof(__fmt), ##__VA_ARGS__ );       \
    }

#endif
