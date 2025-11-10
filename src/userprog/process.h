#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include <stdint.h>

#include "filesys/directory.h"
// At most 8MB can be allocated to the stack
// These defines will be used in Project 2: Multithreading
#define MAX_STACK_PAGES (1 << 11)
#define MAX_THREADS 127

#define MAX_ARGC  128
#define MAX_NAME_LENGTH 128
/* PIDs and TIDs are the same type. PID should be
   the TID of the main thread of the process */
typedef tid_t pid_t;

/* Thread functions (Project 2: Multithreading) */
typedef void (*pthread_fun)(void*);
typedef void (*stub_fun)(pthread_fun, void*);

struct child_process{
   pid_t pid;
   bool create_success;    /* 是否成功创建 */
   bool wait_by_parent;    /* 已被等待 */
   bool alive;             /* 是否还存活 */
   int exit_status;        /* 退出状态 */
   struct list_elem elem;  /* 挂在父进程的child_list */
   struct semaphore sema;  /* 用于等待 */
};

#define MAX_FD_NUM 128
struct file_descriptor{
      int flag;                     /* 控制模式 */
      char name[NAME_MAX];          /* 文件名字 */
      struct file* file_ptr;        /* 文件指针 */
};
struct file_descript_table{
      struct file_descriptor fd[MAX_FD_NUM];  /* 文件描述符数组 */
      bool using[MAX_FD_NUM];       /* 文件指针对应的索引 */
};
/* 给定进程的进程控制块。由于每个进程可以有多个线程，
   我们需要一个独立于线程控制块 (TCB) 的进程控制块 (PCB)。
   进程中的所有 TCB 都将持有指向 PCB 的指针，
   而 PCB 又持有指向进程主线程的指针，主线程是“特殊的”。 */
struct process {
   /* Owned by process.c. */
   uint32_t* pagedir;          /* Page directory. */
   char process_name[16];      /* Name of the main thread */
   struct thread* main_thread; /* Pointer to main thread */

   struct file_descript_table fdt;    /* 文件描述符 */

   struct list child_list;     /* 子进程pid链表 */
   struct child_process* in_parent;  /* 自己在父进程的节点 */

};

struct pass_args{
   int argc;
   char* argv[MAX_ARGC];
};

void userprog_init(void);

pid_t process_execute(const char* file_name);
int process_wait(pid_t);
void process_exit(void);
void process_activate(void);

bool is_main_thread(struct thread*, struct process*);
pid_t get_pid(struct process*);

tid_t pthread_execute(stub_fun, pthread_fun, void*);
tid_t pthread_join(tid_t);
void pthread_exit(void);
void pthread_exit_main(void);

#endif /* userprog/process.h */
