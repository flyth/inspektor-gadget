#include <vmlinux.h>
#include <gadget/kernel_stack_map.h>

 struct {
     __uint(type, BPF_MAP_TYPE_HASH);
     __type(key, u32);
     __type(value, u64);
     __uint(max_entries, 1024);
 } start_times SEC(".maps");

 struct {
     __uint(type, BPF_MAP_TYPE_HASH);
     __type(key, u32);
     __type(value, u64);
     __uint(max_entries, 1024);
 } offcpu_times SEC(".maps");

SEC("tracepoint/sched/sched_switch")
 int trace_sched_switch(struct trace_event_raw_sched_switch *ctx) {
     u64 ts;
     u32 prev_pid, next_pid;

     gadget_get_kernel_stack(ctx);

     // Get the previous task's PID (task that is going off-CPU)
     prev_pid = bpf_get_current_pid_tgid() >> 32;

     // Get the current timestamp
     ts = bpf_ktime_get_ns();

     // Store the start time for the previous task if it's not already stored
     u64 *start_time = bpf_map_lookup_elem(&start_times, &prev_pid);
     if (!start_time) {
         bpf_map_update_elem(&start_times, &prev_pid, &ts, BPF_ANY);
     }

     // Get the next task's PID (task that is coming on-CPU)
     next_pid = ctx->next_pid;

     // Check if the next task was previously off-CPU
     start_time = bpf_map_lookup_elem(&start_times, &next_pid);
     if (start_time) {
         u64 *offcpu_time = bpf_map_lookup_or_try_init(&offcpu_times, &next_pid, 0);
         if (offcpu_time) {
             // Calculate the off-CPU time
             *offcpu_time += ts - *start_time;
         }
         // Remove the start time entry for this task as it's now on-CPU
         bpf_map_delete_elem(&start_times, &next_pid);
     }

     return 0;
 }