#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"

static void syscall_handler(struct intr_frame*);

static void check_valid(uint32_t* args);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

static void syscall_handler(struct intr_frame* f UNUSED) {
  //The caller’s stack pointer is accessible to syscall_handler as the esp member of the struct intr_frame passed to it
  uint32_t* args = ((uint32_t*)f->esp);

  check_valid(args);

  // printf("System call number: %d\n", args[0]); 

  switch(args[0]){
    case SYS_EXIT:
        f->eax = args[1];
        printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);
        process_exit();
        break;

    case SYS_PRACTICE:
        f->eax = args[1] + 1;
        printf("practice add 1\n");
        return;
  }

}

static void check_valid(uint32_t* args){
  /* 验证用户提供指针的有效性 */
  //args是栈顶指针
  struct thread *t = thread_current();
  if(pagedir_get_page(t->pcb->pagedir,args) == NULL){
    process_exit();
  }
}
