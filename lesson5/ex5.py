from __future__ import print_function
from bcc import BPF

prog = """
#include<uapi/linux/ptrace.h>

BPF_HASH(last);

int do_trace(struct pt_regs *ctx){
    u64 *tsp,  key  = 0;
    u64 counter = 0;
    // attempt to read stored timestamp
    tsp = last.lookup(&key);
    if (tsp != NULL){
        counter = *tsp;        
        // output if time less than 1 second
        bpf_trace_printk("%d\\n", *tsp);
        counter ++;
        last.delete(&key);
       
         
    }
    // update stored timestamp
    last.update(&key, &counter);
    
    return 0;
}
"""

b = BPF(text=prog)

b.attach_kprobe(event="sys_sync", fn_name="do_trace")
print("Tracing for quick sync's... Ctrl-C to end")

start = 0
while True:
    (task, pid, cpu, flags, ts, ms) = b.trace_fields()
    print("Catch %s items" % ms)


# Catch 00000001: 0 items
# Catch 00000001: 1 items
# Catch 00000001: 4 items
# Catch 00000001: 5 items
# Catch 00000001: 6 items
# Catch 00000001: 7 items
# Catch 00000001: 16 items


