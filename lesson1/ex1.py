# source: https://github.com/iovisor/bcc/blob/master/docs/tutorial_bcc_python_developer.md#lesson-1-hello-world


from bcc import BPF

BPF(text='int kprobe__sys_clone(void *ctx) { bpf_trace_printk("Hello Word!\\n"); return 0;}').trace_print()

# sudo python ex1.py
# [sudo] password for dsever:
#    systemd-1     [005] .... 22333.459035: 0x00000001: Hello Word!
#    systemd-udevd-864   [000] .... 22333.462088: 0x00000001: Hello Word!
#    systemd-udevd-864   [000] .... 22333.462355: 0x00000001: Hello Word!
#    systemd-udevd-864   [000] .... 22333.462687: 0x00000001: Hello Word!
#    systemd-udevd-864   [000] .... 22333.463111: 0x00000001: Hello Word!
#    systemd-udevd-864   [000] .... 22333.465454: 0x00000001: Hello Word!
#    systemd-udevd-864   [006] .... 22333.523077: 0x00000001: Hello Word!
#    systemd-udevd-864   [006] .... 22333.523630: 0x00000001: Hello Word!
#    systemd-udevd-864   [006] .... 22333.524216: 0x00000001: Hello Word!
#    systemd-udevd-864   [006] .... 22333.524732: 0x00000001: Hello Word!
#    systemd-udevd-864   [006] .... 22333.525682: 0x00000001: Hello Word!
#    systemd-udevd-864   [006] .... 22333.526600: 0x00000001: Hello Word!