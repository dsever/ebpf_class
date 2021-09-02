from __future__ import print_function
from bcc import BPF

prog = """
#include<uapi/linux/ptrace.h>

BPF_HASH(last);

int do_trace(struct pt_regs *ctx){
    u64 ts, *tsp, delta, key  = 0;
    
    // attempt to read stored timestamp
    tsp = last.lookup(&key);
    if (tsp != NULL){
        delta = bpf_ktime_get_ns() - *tsp;
        if (delta < 1000000000 ) {
        // output if time less than 1 second
        bpf_trace_printk("%d\\n", delta / 1000000);
        
        }
        last.delete(&key);
        
    }
    // update stored timestamp
    ts = bpf_ktime_get_ns();
    last.update(&key, &ts);
    return 0;
}
"""

b = BPF(text=prog)

b.attach_kprobe(event="sys_sync", fn_name="do_trace")
print("Tracing for quick sync's... Ctrl-C to end")

start = 0
while True:
    (task, pid, cpu, flags, ts, ms) = b.trace_fields()
    if start == 0:
        start = ts
    ts = ts - start
    print("At time %.2f s: multiple syncs detected, last %s ms ago" % (ts, ms))

# Tracing for quick sync's... Ctrl-C to end
# At time 0.00 s: multiple syncs detected, last 00000001: 593 ms ago
# At time 0.54 s: multiple syncs detected, last 00000001: 535 ms ago
