# source: https://github.com/iovisor/bcc/blob/master/docs/tutorial_bcc_python_developer.md#lesson-1-hello-world


from bcc import BPF

BPF(text='int kprobe__sys_sync(void *ctx) { bpf_trace_printk("Hello Sync\\n"); return 0;}').trace_print()


 # sync-31340 [006] .... 24483.514371: 0x00000001: Hello Sync

