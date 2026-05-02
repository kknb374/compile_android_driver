#ifndef _COMM_H_
#define _COMM_H_

#include <linux/types.h>


#define OP_CMD_CHECK  0x59
#define OP_CMD_PID    0x60
#define OP_CMD_HIDE   0x61
#define OP_CMD_BASE   0x62
#define OP_CMD_READ   0x63
#define OP_CMD_UNHIDE 0x64
#define OP_CMD_HD     0x65
#define OP_CMD_UHD    0x66
#define OP_CMD_HS     0x67
#define OP_CMD_WRITE  0x68
#define OP_CMD_HOOK_ATTACH   0x70
#define OP_CMD_HOOK_DETACH   0x71
#define OP_CMD_HOOK_SET_ROT  0x72
#define OP_CMD_HOOK_STATUS   0x73
#define OP_CMD_WRITE  0x68
#define OP_CMD_SC   0x74

typedef struct _COPY_MEMORY {
    pid_t pid;
    uintptr_t addr;
    void *buffer;
    size_t size;
} COPY_MEMORY, *PCOPY_MEMORY;

typedef struct _MODULE_BASE {
    pid_t pid;
    char *name;
    uintptr_t base;
} MODULE_BASE, *PMODULE_BASE;

typedef struct _GET_PID {
    char *name;
    pid_t pid;
} GET_PID, *PGET_PID;

typedef struct _HIDE_PID {
    pid_t pid;
} HIDE_PID, *PHIDE_PID;

typedef struct _HIDE_SO {
    char *name;
} HIDE_SO, *PHIDE_SO;

typedef struct _SC_PID {
    pid_t pid;
} SC_PID, *PSC_PID;

#define STACK_ROT_MAX   12

typedef struct _HOOK_ATTACH {
    pid_t           pid;
    unsigned long   target_addr;
} HOOK_ATTACH, *PHOOK_ATTACH;

typedef struct _HOOK_SET_ROT {
    __u32   rot[3];
    __u32   stack_rot[STACK_ROT_MAX];
    __u32   stack_count;
    __u32   stack_offset;
} HOOK_SET_ROT, *PHOOK_SET_ROT;

typedef struct _HOOK_STATUS {
    __u8    active;
    __u8    armed;
    pid_t   pid;
    unsigned long vaddr;
    unsigned long target_addr;
    __u32   rot[3];
    __u32   stack_rot[3];
    __u32   stack_count;
    __u32   stack_offset;
    __u64   hit_count;
} HOOK_STATUS, *PHOOK_STATUS;


#endif /* _COMM_H_ */
