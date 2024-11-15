#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <gadget/kernel_stack_map.h>
#include <gadget/types.h>
#include <gadget/macros.h>
#include <asm-generic/errno.h>

#define MINBLOCK_US    1ULL
#define MAXBLOCK_US    99999999ULL

#define MAX_ENTRIES 10240

const volatile pid_t target_pid = 0;
GADGET_PARAM(target_pid);

typedef __u32 gadget_user_stack;

struct mkey {
    __u32 pid;
    __u32 tgid;
    gadget_user_stack user_stack_id_raw;
    gadget_kernel_stack kernel_stack_id_raw;
    char name[TASK_COMM_LEN];
};

struct mval {
    __u64 count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct mkey);
    __type(value, struct mval);
} counts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, __u64);
} start SEC(".maps");

GADGET_MAPITER(counts, counts);

static __always_inline void *
bpf_map_lookup_or_try_init(void *map, const void *key, const void *init) {
	void *val;
	long err;
	val = bpf_map_lookup_elem(map, key);
	if (val)
		return val;
	err = bpf_map_update_elem(map, key, init, BPF_NOEXIST);
	if (err && err != -EEXIST)
		return 0;
	return bpf_map_lookup_elem(map, key);
}

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
	__uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(u64));
	__uint(max_entries, KERNEL_STACK_MAP_MAX_ENTRIES);
} ig_ustack SEC(".maps");

/* Returns the user stack id, positive or zero on success, negative on failure */
static __always_inline long gadget_get_user_stack(void *ctx)
{
	return bpf_get_stackid(ctx, &ig_ustack, BPF_F_USER_STACK);
}

SEC("kprobe/finish_task_switch.isra.0")
int BPF_KPROBE(oncpu, struct task_struct *prev) {
    u32 pid = BPF_CORE_READ(prev, pid);
    u32 tgid = BPF_CORE_READ(prev, tgid);
    u64 ts, *tsp;

    // record previous thread sleep time
    if (target_pid == 0 || pid == target_pid) {
        ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&start, &pid, &ts, 0);
    }

    // get the current thread's start time
    pid = bpf_get_current_pid_tgid();
    if (target_pid != 0 && target_pid != pid) {
        return 0;
    }

    tgid = bpf_get_current_pid_tgid() >> 32;
    tsp = bpf_map_lookup_elem(&start, &pid);

    if (tsp == 0) {
        return 0;
    }

    // calculate current thread's delta time
    u64 t_start = *tsp;
    u64 t_end = bpf_ktime_get_ns();
    bpf_map_delete_elem(&start, &pid);

    if (t_start > t_end) {
        // TODO: warn
        return 0;
    }

    u64 delta = t_end - t_start;
    delta = delta / 1000;
    if ((delta < MINBLOCK_US) || (delta > MAXBLOCK_US)) {
        return 0;
    }

    // create map key
    struct mkey key = {};
    key.pid = pid;
    key.tgid = tgid;
    key.user_stack_id_raw = gadget_get_user_stack(ctx);
    key.kernel_stack_id_raw = gadget_get_kernel_stack(ctx);
    bpf_get_current_comm(&key.name, sizeof(key.name));

    struct mval zero = {0};
    struct mval *counter = bpf_map_lookup_or_try_init(&counts, &key, &zero);
    if (counter == 0) {
        return 0;
    }
    __sync_fetch_and_add(&counter->count, delta);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";