package manager

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type config_entry_t -type event_context_t -type event_config_t  -no-global-types -target bpfel ebpf ../tracee.bpf.c -- -I.. -D__TARGET_ARCH_x86 -DDEBUG_K
