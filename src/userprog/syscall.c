#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"


static void syscall_handler(struct intr_frame*);

static void check_valid_arg(void* args);
static void check_valid_str(const char* str);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

static uint32_t syscall_exec(const char* file_name){
    // const char* file_name = (char*)args[1];
    int exec_pid = process_execute(file_name);
    return exec_pid;
}
static uint32_t syscall_wait(pid_t pid){
    return process_wait(pid);
}
//arg[0]是调用号，其余是参数
static void syscall_handler(struct intr_frame* f UNUSED) {
  //The caller’s stack pointer is accessible to syscall_handler as the esp member of the struct intr_frame passed to it
  //调用者的堆栈指针可以通过传递给它的 struct intr_frame 的 esp 成员访问。指针数组
  uint32_t *args = ((uint32_t*)f->esp);//32bit width

  // printf("arg0 = %d, arg1 = %s\n",args[0],(char*)args[1]);

  check_valid_arg(args);//检查栈顶指针是否有问题


  switch(args[0]){
    case SYS_HALT:
        shutdown_power_off();
        break;
        
    case SYS_EXIT:
        f->eax = args[1];
        printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);
        process_exit();
        break;
    
    case SYS_EXEC:
        check_valid_str((char*)args[1]);
        f->eax = syscall_exec((char*)args[1]);
        break;
      
    case SYS_WAIT:
        f->eax = syscall_wait(args[1]);
        break;


    case SYS_PRACTICE:
        f->eax = args[1] + 1;
        printf("practice\n");
        break;

    // case SYS_FORK:


  }

}

/* 验证指针是否在用户空间、指针指向的地址是否是已分配内存的 */
static void check_valid_arg(void* args){
    struct thread *t = thread_current();
    if(args == NULL || pagedir_get_page(t->pcb->pagedir,args) == NULL)
    {//pgdir_getpage已经检查了是否在uaddr
        // printf("bad ptr\n");
        process_exit();
    }
    // else{
    //     printf("ptr is OK\n");
    // }
}
static void check_valid_str(const char* str){
    struct thread *t = thread_current();
    if(str == NULL){
        printf("bad str\n");
        process_exit();
    }

    char* p = str;
    while(*p != '\0'){
        if(pagedir_get_page(t->pcb->pagedir,p) == NULL){
            printf("bad string\n");
        }
        p++;
    }
    printf("str : %s is OK\n",str);
}


