from bcc import BPF


prog = """

int  hello(void *ctx){
    bpf_trace_printk("hello word!!\\n");
    return 0;
    } 
"""

b = BPF(text=prog)

b.attach_kprobe(event="sys_clone", fn_name="hello")

print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))


# TIME(s)            COMM             PID    MESSAGE
# 25867.465804000    systemd          1      00000001: hello word!!
# 25867.471139000    systemd-udevd    864    00000001: hello word!!
# 25867.472083000    systemd-udevd    864    00000001: hello word!!
# 25867.473112000    systemd-udevd    864    00000001: hello word!!
# 25867.474106000    systemd-udevd    864    00000001: hello word!!
# 25867.476364000    systemd-udevd    864    00000001: hello word!!
