#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
// #include "userprog/"

static void syscall_handler(struct intr_frame*);

static void check_valid_arg(uint32_t* args);
static void check_valid_ptr(const char * str);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

static void syscall_handler(struct intr_frame* f UNUSED) {
  //The caller’s stack pointer is accessible to syscall_handler as the esp member of the struct intr_frame passed to it
  //调用者的堆栈指针可以通过传递给它的 struct intr_frame 的 esp 成员访问。
  uint32_t* args = ((uint32_t*)f->esp);

  check_valid_arg(args);//检查栈顶指针是否有问题
  // printf("arg0 = %d, arg1 = %d\n",args[0],args[1]);

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
        const char* file_name = (char*)args[1];
        //检查参数
        f->eax = -1;
        check_valid_arg(file_name);

      
        int exec_pid = process_execute(file_name);
        printf("exe \n");
        f->eax = exec_pid;
        break;
      
    case SYS_WAIT:
        int wait_pid = args[1];
        f->eax = process_wait(wait_pid);
        break;


    case SYS_PRACTICE:
        f->eax = args[1] + 1;
        break;

  }

}

/* 验证指针是否在用户空间、指针指向的地址是否是已分配内存的 */
static void check_valid_arg(uint32_t* args){
    //args是栈顶指针
    struct thread *t = thread_current();
    if(args != NULL || pagedir_get_page(t->pcb->pagedir,args) == NULL  
            || !is_user_vaddr(args))
    {
      process_exit();
    }
}
/* 验证参数指针是否在用户空间、是否跨页超出用户空间 */
static void check_valid_ptr(const char * str){
    struct thread *t = thread_current();
        
        // 检查字符串起始地址
        if (str == NULL || !is_user_vaddr(str)) {
            process_exit();
        }
        
        // 逐字节检查，直到遇到 '\0'
        const char* p = str;
        while (true) {
            // 检查当前字节所在地址
            if (!is_user_vaddr(p) || 
                pagedir_get_page(t->pcb->pagedir, p) == NULL) {
                process_exit();
            }
            
            // 读取当前字节（此时已确认安全）
            if (*p == '\0') {
                break;
            }
            p++;
        }

}

