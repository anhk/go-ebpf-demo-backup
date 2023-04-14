#pragma once

typedef unsigned int uint32_t;
typedef unsigned long uint64_t;
typedef unsigned char __u8;
typedef short int __s16;
typedef short unsigned int __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long int __s64;
typedef long long unsigned int __u64;
typedef __u8 u8;
typedef __s16 s16;
typedef __u16 u16;
typedef __s32 s32;
typedef __u32 u32;
typedef __s64 s64;
typedef __u64 u64;
typedef __u16 __le16;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u32 __wsum;

#define __TARGET_ARCH_x86
#if defined(__TARGET_ARCH_x86)
struct pt_regs {
	/*
	 * C ABI says these regs are callee-preserved. They aren't saved on kernel entry
	 * unless syscall needs a complete, fully filled "struct pt_regs".
	 */
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long rbp;
	unsigned long rbx;
	/* These regs are callee-clobbered. Always saved on kernel entry. */
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long rax;
	unsigned long rcx;
	unsigned long rdx;
	unsigned long rsi;
	unsigned long rdi;
	/*
	 * On syscall entry, this is syscall#. On CPU exception, this is error code.
	 * On hw interrupt, it's IRQ number:
	 */
	unsigned long orig_rax;
	/* Return frame for iretq */
	unsigned long rip;
	unsigned long cs;
	unsigned long eflags;
	unsigned long rsp;
	unsigned long ss;
	/* top of stack page */
};
#endif /* __TARGET_ARCH_x86 */


#define __section(NAME) __attribute__((section(NAME), used))

#ifndef barrier
# define barrier()		asm volatile("": : :"memory")
#endif

#define BPF_MAP_TYPE_HASH (1)
#define BPF_MAP_TYPE_ARRAY (2)
#define BPF_MAP_TYPE_PROG_ARRAY (3)
#define BPF_MAP_TYPE_PERF_EVENT_ARRAY (4)
#define BPF_MAP_TYPE_ARRAY_OF_MAPS (12)
#define BPF_MAP_TYPE_HASH_OF_MAPS (13)
#define BPF_MAP_TYPE_RINGBUF (27)


#define BPF_F_NO_PREALLOC (1U << 0)
#define BPF_F_CURRENT_CPU (0xffffffffULL)


static void *(*map_lookup_elem)(const void *map, const void *key) = (void *)1;

static long (*map_update_elem)(const void *map, const void *key, const void *value, uint64_t flags) = (void *)2;

static long (*trace_printk)(const char *fmt, uint32_t fmt_size, ...) = (void *)6;

static long (*tail_call)(void *ctx, void *prog_array_map, uint32_t index) = (void *)12;

static int (*perf_event_output)(const void *ctx, const void *map, uint64_t index, const void *data, uint64_t size) = (void *)25;

static uint32_t (*get_smp_processor_id)(void) = (void *)8;

static long (*for_each_map_elem)(const void *map, void *callback_fn, void *callback_ctx, uint64_t flags) = (void *)164;

#define get_prandom_u32 bpf_get_prandom_u32
