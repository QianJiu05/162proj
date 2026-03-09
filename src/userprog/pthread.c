#include "userprog/pthread.h"
#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

#include "userprog/syscall.h"

static thread_func start_pthread NO_RETURN;
// bool setup_thread(void (**eip)(void), void** esp);

/* 启动一个新线程，该线程使用新的用户栈运行 SF，
  并接受TF 和 ARG 作为用户栈上的参数。
  这个新线程可能在 pthread_execute() 返回之前被调度（甚至可能退出）。
  返回新线程的 TID，如果线程无法正确创建，则返回 TID_ERROR。
  并且应该类似于 process_execute()。
*/
tid_t pthread_execute(stub_fun sf , pthread_fun tf , const void* arg ) {
    struct pthread_create_arg* thread_arg = calloc(sizeof(struct pthread_create_arg),1);
    if(thread_arg == NULL){
        return TID_ERROR;
    }
    thread_arg->sf = sf;
    thread_arg->tf = tf;
    thread_arg->arg = arg;
    sema_init(&thread_arg->sema,0);
    thread_arg->p = thread_current()->pcb;

    /* 由于thread_create添加了优先级调度，如果子线程优先级高于父线程，
      会直接让出CPU;或子线程与父线程优先级相同，父线程时间片耗尽，
      导致还没运行到sema_down，子线程就sema_up了，
      所以要先修改父线程优先级，保证先进入睡眠 */
    int priority = thread_get_priority();
    thread_set_priority(PRI_DEFAULT + 1);
    tid_t tid = thread_create("pthread", PRI_DEFAULT, start_pthread, thread_arg);
    if(tid == TID_ERROR){
        free(thread_arg);
        return TID_ERROR;
    }
    sema_down(&thread_arg->sema);
    thread_set_priority(priority);

    free(thread_arg);
    return tid;
}

/* 一个用于创建新用户线程并启动它的线程函数。它负责将自身添加到PCB的线程列表中。
此函数类似于`start_process()`。
  start_process主要进行参数填充，pcb建立以及初始化， */
static void start_pthread(void* exec_ ) {
    bool success = false;
    struct pthread_create_arg* exec = (struct pthread_create_arg*)exec_;
    struct intr_frame if_;
    struct thread *t = thread_current();
    
    t->pcb = exec->p;

    /* 激活页表 (共享进程的页表) ,如果不激活，MMU无法转换地址 */
    process_activate();

    memset(&if_, 0, sizeof if_);
    if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
    if_.cs = SEL_UCSEG;
    if_.eflags = FLAG_IF | FLAG_MBS;
    
    /* 把esp指向栈顶 */
    success = setup_thread(&if_.eip,&if_.esp);
    if(success){
      /* 压栈，  [arg]
                [tf]
                [Ret Addr] <-esp 指向这里
      并且 eip 指向 sf */
      char* esp = (char*)if_.esp;
      esp -= 4; *(void**)esp = exec->arg;
      esp -= 4; *(void**)esp = exec->tf;
      esp -= 4; *(void**)esp = 0;
      
      if_.esp = (void*)esp;
      if_.eip = exec->sf;
    }else{
        sema_up(&exec->sema);
        thread_exit();
    }
    
    t->tsb = calloc(1,sizeof( struct thread_status_block));
    t->tsb->tid = t->tid;
    t->tsb->th = t;
    t->tsb->been_joined = false;
    t->tsb->finished = false;
    sema_init(&t->tsb->join_sema,0);

    enum intr_level old_level = intr_disable();
    list_push_back(&t->pcb->multi_thread,&t->tsb->pcb_elem);
    intr_set_level(old_level);
    
    /* 唤醒父线程 */
    exec->success = success;
    sema_up(&exec->sema);

    asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
    NOT_REACHED();
}

/* 等待 TID 为 TID 的线程终止，前提是该线程是在同一进程中创建的，
  并且尚未被等待过。成功时返回 TID，失败时立即返回 TID_ERROR，
  不等待。 */
tid_t pthread_join(tid_t tid ) { 
    struct process * p = thread_current()->pcb;

    struct thread_status_block* tsb = NULL;
    bool should_do_clean = true;

    enum intr_level old_level;

    if (p->main_thread->tid == tid) {
        tsb = p->main_thread->tsb;
        should_do_clean = false;
    } else {

        /* 修复：全程关中断保护查找和状态检查，防止竞态 */
        old_level = intr_disable();
        for(struct list_elem* e = list_begin(&p->multi_thread);
          e != list_end(&p->multi_thread); e = list_next(e))
        {
            struct thread_status_block* multi = list_entry(e, struct thread_status_block, pcb_elem);
            if(multi->tid == tid){
                tsb = multi;
                break;
            }
        }

    }
    intr_set_level(old_level);

    /* 找不到tsb */
    if(tsb == NULL){return TID_ERROR;}

    if(tsb->been_joined == true){ return TID_ERROR; }

    old_level = intr_disable();
    /* 已完成的,非main，直接清理并return */
    if(tsb->finished == true){
        if(should_do_clean) {
            list_remove(&tsb->pcb_elem);
            intr_set_level(old_level);
            free(tsb);
        }
        return tid;
    }

    /* 未完成:tsb->finished == false */
    tsb->been_joined = true;
    sema_down(&tsb->join_sema);

    /* 醒了之后清理这个block,用中断防止竞态
        main的tsb不能被clean，因为不在multi_list */
    if(should_do_clean) {
        list_remove(&tsb->pcb_elem);
        intr_set_level(old_level);
        free(tsb);
    }

    return tid;
}

/* 释放当前线程的资源。大多数资源将在 thread_exit() 时释放，
  因此我们只需释放线程的用户空间栈。唤醒所有在此线程上等待的线程。
  主线程不应使用此函数。请参见下面的 pthread_exit_main()。 */
void pthread_exit(void) {
  struct thread* t = thread_current();
  // printf("pthread exit, tid = %d\n",t->tid);
    if(t == t->pcb->main_thread){
        if(t->tsb->been_joined){
            // printf("main been joined,sema up waiter\n");
            sema_up(&t->tsb->join_sema);
        }
        pthread_exit_main();
        return;//not reached
    }
    
    void* kpage = pagedir_get_page(t->pcb->pagedir,t->user_stack);
    palloc_free_page(kpage);
    pagedir_clear_page(t->pcb->pagedir,t->user_stack);

    /* 保存退出的status */
    t->tsb->finished = true;
    if(t->tsb->been_joined){
      sema_up(&t->tsb->join_sema);
    }
    t->tsb->th = NULL;//线程要退出了
    thread_exit();
}

/* 仅当主线程显式调用 pthread_exit 时才使用。
  主线程应等待进程中的所有线程正常终止后，才能退出自身。
  当它退出自身时，除了执行 pthread_exit 中规定的所有必要任务外，
  还必须终止进程。*/
void pthread_exit_main(void) {
  // printf("pthread exit main\n");
    struct thread* t = thread_current();
    if(t != t->pcb->main_thread) return;

    t->tsb->finished = true;

    struct process* p = t->pcb;
    /* 由于pthread_join会破坏multi_thread的结构，所以不能使用list_next来迭代
      应该每次都取head */
    while(!list_empty(&p->multi_thread)){
        struct list_elem *e = list_front(&p->multi_thread);
        bool handled = false;

        while(e != list_end(&p->multi_thread)){
            struct thread_status_block* tsb = list_entry(e, struct thread_status_block,pcb_elem);
            
            /* 被join的不要处理 */
            if(tsb->been_joined == true) {
                e = list_next(e);
                continue;
            }

            /* !been_joined */
            if(tsb->finished == false) {
                /* pthread_join醒了之后直接把tsb清理掉了,迭代器失效了要从头获取 */
                pthread_join(tsb->tid);
                handled = true;
            } else {/* finish=true，joined=false，手动清理tsb,在清理前可以使用迭代器 */
                enum intr_level old_level = intr_disable();
                e = list_next(e);
                list_remove(&tsb->pcb_elem);
                intr_set_level(old_level);
                free(tsb);
            }

            if(handled) { break; }

        }
    }
    /* 主线程不需要释放stack，因为process_exit会释放 */
    syscall_exit(0);
}