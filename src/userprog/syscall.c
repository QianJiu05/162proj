#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"

static void syscall_handler(struct intr_frame*);

static void check_valid_num(uint32_t* args);
static void check_valid_str(const char* str);
static void check_valid_buffer(const void* buffer, size_t size);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

static int32_t syscall_exit(int status){
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, status);
    process_exit();
    // return thread_current()->pcb->
    return 0;
}
static uint32_t syscall_exec(const char* file_name){
    // const char* file_name = (char*)args[1];
    int exec_pid = process_execute(file_name);
    return exec_pid;
}
static uint32_t syscall_wait(pid_t pid){
    return process_wait(pid);
}
static int syscall_write(int fd, void* buffer, size_t size){
    int ret = -1;
    if(fd == STDOUT_FILENO){
        putbuf(buffer,size);
        ret = 0;
    }
    return ret;
}
//arg[0]是调用号，其余是参数
static void syscall_handler(struct intr_frame* f UNUSED) {
  //The caller’s stack pointer is accessible to syscall_handler as the esp member of the struct intr_frame passed to it
  //调用者的堆栈指针可以通过传递给它的 struct intr_frame 的 esp 成员访问。指针数组
  uint32_t *args = ((uint32_t*)f->esp);//32bit width

  // printf("arg0 = %d, arg1 = %s\n",args[0],(char*)args[1]);

  check_valid_num(&args[0]);//检查栈顶指针是否有问题


  switch(args[0]){
    case SYS_HALT:
        shutdown_power_off();
        break;
        
    case SYS_EXIT:
        check_valid_num(&args[1]);
        f->eax = args[1];
        syscall_exit(args[1]);
        break;
    
    case SYS_EXEC:
        // check_valid_str((char*)args[1]);
        f->eax = syscall_exec((char*)args[1]);
        break;
      
    case SYS_WAIT:
        check_valid_num(&args[1]);
        f->eax = syscall_wait(args[1]);
        break;

    case SYS_WRITE:
        check_valid_num(&args[1]);
        check_valid_num(&args[3]);
        check_valid_buffer((void*)args[2],args[3]);
        f->eax = syscall_write((int)args[1],(void*)args[2],(size_t)args[3]);
        break;



    case SYS_PRACTICE:
        check_valid_num(&args[1]);
        f->eax = args[1] + 1;
        break;

    // case SYS_FORK:


  }

}

/* 验证num是否在用户空间、指针指向的地址是否是已分配内存的 */
static void check_valid_num(uint32_t* num){
    struct thread *t = thread_current();

    if(num == NULL || pagedir_get_page(t->pcb->pagedir,num) == NULL)
    {//pgdir_getpage已经检查了是否在uaddr
        process_exit();
    }
    void* this_byte = (void*)num;
    for(int i = 1; i <= 3; i++){
        this_byte = (void*)((char*)this_byte + i);
        if(num == NULL || pagedir_get_page(t->pcb->pagedir,this_byte) == NULL)
        {//pgdir_getpage已经检查了是否在uaddr
            // process_exit();
            syscall_exit(-1);
        }
    }
}
static void check_valid_str(const char* str){
    struct thread *t = thread_current();
    if(str == NULL){
        // process_exit();
        syscall_exit(-1);
    }

    char* p = str;
    while(*p != '\0'){
        if(pagedir_get_page(t->pcb->pagedir,p) == NULL){
            // printf("bad string\n");
            // process_exit();
            syscall_exit(-1);
        }
        p++;
    }
}
static void check_valid_buffer(const void* buffer, size_t size){
    if(buffer == NULL){
        // printf("empty ptr\n");
        // process_exit();
        syscall_exit(-1);
    }

    if(size == 0)return;

    struct thread *t = thread_current();

    if(pagedir_get_page(t->pcb->pagedir,buffer) == NULL){
        // printf("bad buffer\n");
        syscall_exit(-1);
    }

    void* end_buffer = (void*)(char*)buffer + size - 1;//指向最后一个字节

    void* start = pg_round_down(buffer);
    void* end = pg_round_down(end_buffer);

    if(start != end){
        void* page = (void*)(char*)start + PGSIZE;
        while(page <= end){
            if(pagedir_get_page(t->pcb->pagedir,page) == NULL){
                syscall_exit(-1);
            }
            page = (void*)(char*)page + PGSIZE;
        }
    }    
}


