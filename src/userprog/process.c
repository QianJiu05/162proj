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

#include "threads/pte.h"
#include "filesys/file.h"

static thread_func start_process NO_RETURN;
static thread_func start_pthread NO_RETURN;
bool load(struct pass_args* arg, void (**eip)(void), void** esp);
bool setup_thread(void (**eip)(void), void** esp);
extern initial_thread;
struct lock file_lock;
struct lock user_sema_lock;
struct lock pthread_lock;

static bool copy_memory(uint32_t* parent,uint32_t* child);
static void start_fork_process(struct child_process *chpcb);
static void release_holding_lock(struct list* list);

/* 通过确保主线程拥有最小的程序控制块 (PCB) 来初始化系统中的用户程序，
   以便它能够执行并等待第一个用户进程。如果主线程需要这些成员，
   则对 PCB 的任何新增内容也应在此处初始化。 
*/
void userprog_init(void) {
    struct thread* t = thread_current();
    bool success;

    /* 分配进程控制块重要的是，这里调用的是 calloc 而不是 malloc，
       这样才能保证在 t->pcb 被赋值时，
       t->pcb->pagedir 为 NULL（内核的页目录），
       因为定时器中断随时可能发生并激活我们的页目录 */
    t->pcb = calloc(sizeof(struct process), 1);
    success = t->pcb != NULL;
    
    /* 这里要对初始进程进行pcb建立，
        不然第一个process_exec在退出后返回不了init */
    if(success){
        list_init(&t->pcb->child_list);
        strlcpy(t->pcb->process_name, "init", sizeof(t->pcb->process_name));
        t->pcb->in_parent = NULL;
        t->pcb->main_thread = t;
        t->pcb->pagedir = NULL;
        t->pcb->file_lock = NULL;
        memset(&t->pcb->fdt,0,sizeof(t->pcb->fdt));
    }
    lock_init(&file_lock);
    lock_init(&user_sema_lock);
    lock_init(&pthread_lock);

    /* Kill the kernel if we did not succeed */
    ASSERT(success);
}
static struct pass_args* init_arg(struct pass_args *arg) {
    arg->argc = 0;
    for(int i = 0; i < MAX_ARGC; i++){
        arg->argv[i] = NULL;
    }
    return arg;
}
static void parse_args(const char* file_name, struct pass_args *arg){
    if(file_name == NULL || arg == NULL)return;

    int len = strlen(file_name);
    // char cmd[len + 1];
    char* cmd = malloc(sizeof(char)*(len+1));
    strlcpy(cmd,file_name,len+1);
    
    char *token, *save_ptr;
    int word_len;
    int cnt = 0;

    for (token = strtok_r (cmd, " ", &save_ptr); token != NULL;
            token = strtok_r (NULL, " ", &save_ptr))
    {
        word_len = strlen(token);

        if(cnt > MAX_ARGC -1)break;//argv 0~127
        arg->argv[cnt] = malloc(sizeof(char) * (word_len+1));
        strlcpy(arg->argv[cnt],token,word_len+1);
        cnt++;
    }
    arg->argv[cnt] = NULL;//存入NULL表示结束
    arg->argc = cnt;
    free(cmd);
}
struct process_exec_arg{
    char* fn_copy;
    struct child_process* child;
};
static int16_t get_fn_len(const char* file_name){
    int16_t fn_len = 0;
    while(file_name[fn_len] != ' ' && file_name[fn_len] != '\0'){
        fn_len++;
    }
    return fn_len;
}
static void copy_fn_to_fp(char* file_name,char* file_path,int fn_len){
    for(int i = 0; i < fn_len; i++){
        file_path[i] = file_name[i];
    }
    file_path[fn_len] = '\0';
}
/* 启动一个新线程，运行从FILENAME 加载的用户程序。
   新线程可能在 process_execute() 返回之前被调度（甚至可能退出）。
   返回新进程的进程 ID，如果无法创建线程，则返回 TID_ERROR。*/
pid_t process_execute(const char* file_name) {
    char* fn_copy;
    tid_t tid;

    /* Make a copy of FILE_NAME.
      Otherwise there's a race between the caller and load(). */
    fn_copy = palloc_get_page(0);
    if (fn_copy == NULL)
        return TID_ERROR;
    strlcpy(fn_copy, file_name, PGSIZE);

    int16_t fn_len = get_fn_len(file_name);

    char* file_path = malloc(sizeof(char)*(fn_len+1));
    copy_fn_to_fp(file_name,file_path,fn_len);

    /* 此时还在父进程中 */
    struct thread* t = thread_current();
    struct child_process *child = calloc(1,sizeof(struct child_process));
    if(child == NULL){
        printf("calloc failed\n");
        return TID_ERROR;
    }
    child->wait_by_parent = false;
    child->alive = false;
    child->create_success = false;
    child->exit_status = -1;
    sema_init(&(child->sema),0);
    list_push_back(&(t->pcb->child_list),&(child->elem));//要关中断吗？

    struct process_exec_arg* proc_arg = calloc(1,sizeof(struct process_exec_arg));
    proc_arg->child = child;
    proc_arg->fn_copy = fn_copy;

    /* Create a new thread to execute FILE_NAME. */
    tid = thread_create(file_path, PRI_DEFAULT, start_process, proc_arg);
    if (tid == TID_ERROR){
        palloc_free_page(fn_copy);
        return TID_ERROR;
    }

    child->pid = tid;

    /* 让父进程进入等待，创建子进程后唤醒父进程，
        不论是否成功，然后初始化child_PCB并返回tid */
    sema_down(&child->sema);
    free(proc_arg);
    free(file_path);

    if (child->create_success == false) {
        list_remove(&child->elem);
        free(child);
        return TID_ERROR;
    }
    return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void start_process(void* _arg) {
    struct process_exec_arg* proc_arg = (struct process_exec_arg*)_arg;

    struct pass_args local;
    init_arg(&local);
    parse_args(proc_arg->fn_copy,&local);
    
    struct thread* t = thread_current();
    struct intr_frame if_;
    bool success, pcb_success;

    /* Allocate process control block */
    struct process* new_pcb = calloc(1,sizeof(struct process));
    success = pcb_success = new_pcb != NULL;

    /* Initialize process control block */
    if (success) {
        // Ensure that timer_interrupt() -> schedule() -> process_activate()
        // does not try to activate our uninitialized pagedir
        new_pcb->pagedir = NULL;
        t->pcb = new_pcb;

        // Continue initializing the PCB as normal
        t->pcb->main_thread = t;
        strlcpy(t->pcb->process_name, t->name, sizeof t->name);

        list_init(&(t->pcb->child_list));
        list_init(&t->pcb->multi_thread);
        t->pcb->file_lock = NULL;

        t->tsb = calloc(1,sizeof( struct thread_status_block));
        t->tsb->tid = t->tid;
        t->tsb->th = t;
        t->tsb->been_joined = false;
        t->tsb->finished = false;
        sema_init(&t->tsb->join_sema,0);

        if (proc_arg->child != NULL) {
            t->pcb->in_parent = proc_arg->child;
            proc_arg->child->alive = true;
            proc_arg->child->create_success = true;
        }
    }

    /* Initialize interrupt frame and load executable. */
    if (success) {
      memset(&if_, 0, sizeof if_);
      if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
      if_.cs = SEL_UCSEG;
      if_.eflags = FLAG_IF | FLAG_MBS;
      success = load(&local, &if_.eip, &if_.esp);
    }

    /* Handle failure with succesful PCB malloc. Must free the PCB */
    if (!success && pcb_success) {
      // Avoid race where PCB is freed before t->pcb is set to NULL
      // If this happens, then an unfortuantely timed timer interrupt
      // can try to activate the pagedir, but it is now freed memory
      struct process* pcb_to_free = t->pcb;
      t->pcb = NULL;
      free(pcb_to_free);
    }

    /* Clean up. Exit on failure or jump to userspace */
    palloc_free_page(proc_arg->fn_copy);//传进来的是fn copy as filename

    if (!success) {
        if(proc_arg->child != NULL){
            proc_arg->child->exit_status = -1;
            proc_arg->child->alive = false;
            proc_arg->child->create_success = false;
            sema_up(&proc_arg->child->sema);
        }
        thread_exit();//这里没有释放pcb的pd。会造成内存泄漏嘛?-->process_exit?
    }
    sema_up(&proc_arg->child->sema);//加载成功也要释放信号量

    /* 通过模拟中断返回来启动用户进程，
    中断由 intr_exit 实现（位于threads/intr-stubs.S 中）。
    由于 intr_exit 的所有参数都以 `struct intr_frame` 的形式放在栈上，
    因此我们只需将栈指针 (%esp) 指向栈帧，然后跳转到该栈帧即可。 */
    asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
    NOT_REACHED();
}

/* 等待进程 ID 为 child_pid 的进程终止，并返回其退出状态。
   如果该进程是由内核终止的（即由于异常而被杀死），则返回 -1。
   如果 child_pid 无效，或者它不是调用进程的子进程，或者如果
   已对给定的 PID 成功调用过 process_wait()，则立即返回 -1，无需等待。
 */
int process_wait(pid_t child_pid) {
    struct thread* t = thread_current();
    struct list* child = &(t->pcb->child_list);

    /* 没有子进程 */
    if( list_empty(child) ){ return -1; }
    /* 遍历子进程list找pid */
    for(struct list_elem* e = list_begin(child); 
            e != list_end(child); e = list_next(e))
    {
        struct child_process *p = list_entry(e,struct child_process,elem);
        if (child_pid == p->pid) {
            /* 已经死了 */
            if(p->alive == false){
                int status = p->exit_status;
                list_remove(e);
                free(p);
                return status;
            }

            /* 已经被等待，立刻return-1 */
            if (p->wait_by_parent == true) { return -1; }

            /* 没死&没被等待，进入等待 */
            p->wait_by_parent = true;
            sema_down(&p->sema);//这里进入等待

            /* 醒来后，获取退出状态并清理 */
            int status = p->exit_status;
            list_remove(e);
            free(p);
            return status;
        }    
    }    
    /* 找不到，不是直接子进程，返回-1 */
    return -1;
}

/* Free the current process's resources. */
void process_exit(void) {
    struct thread* cur = thread_current();
    uint32_t* pd;

    /* If this thread does not have a PCB, don't worry */
    if (cur->pcb == NULL) {
        thread_exit();
        NOT_REACHED();
    }

    /* 强制终止所有其他线程 */
    if (!list_empty(&cur->pcb->multi_thread)) {
        struct list_elem *e = list_begin(&cur->pcb->multi_thread);
        
        while (e != list_end(&cur->pcb->multi_thread)) {
            struct thread_status_block* tsb = list_entry(e, struct thread_status_block, pcb_elem);
            struct thread* t = tsb->th;
            
            e = list_next(e);
            
            /* 如果线程还活着，强制终止它 */
            if (t != NULL && t != cur && t->status != THREAD_DYING) {
                /* 标记线程为即将死亡 */
                enum intr_level old_level = intr_disable();
                
                /* 从等待队列\就绪队列中移除 */
                if (t->status == THREAD_BLOCKED || t->status == THREAD_READY) {
                    list_remove(&t->elem);
                }

                release_holding_lock(&t->holding_lock);
                
                /* 标记为死亡状态 */
                t->status = THREAD_DYING;
                list_remove(&t->allelem);

                /* 释放线程 */
                if (t != initial_thread) {
                    palloc_free_page(t);
                }
                
                intr_set_level(old_level);
            }
        }
        
        /* 清理所有 TSB */
        while (!list_empty(&cur->pcb->multi_thread)) {
            e = list_pop_front(&cur->pcb->multi_thread);
            struct thread_status_block* tsb = list_entry(e, struct thread_status_block, pcb_elem);
            free(tsb);
        }
    }
    /* 退出主线程 */
    if(cur != cur->pcb->main_thread){
        struct thread* main = cur->pcb->main_thread;
        if (main->status == THREAD_BLOCKED || main->status == THREAD_READY) {
            list_remove(&main->elem);
        }
        release_holding_lock(&main->holding_lock);

        /* 标记为死亡状态 */
        main->status = THREAD_DYING;
        list_remove(&main->allelem);
    }

    
    /* Destroy the current process's page directory and switch back
      to the kernel-only page directory. */
    pd = cur->pcb->pagedir;
    if (pd != NULL) {
      /*  正确的顺序至关重要。在切换页面目录之前，我们必须将cur->pcb->pagedir 设置为 NULL，
          这样定时器中断就无法切换回进程页面目录。我们必须先激活基页面目录，然后再销毁进程的页面目录，
          否则，我们当前活动的页面目录将是已被释放（并清空）的页面目录。 */
        cur->pcb->pagedir = NULL;
        pagedir_activate(NULL);
        pagedir_destroy(pd);
    }

    /* Free the PCB of this process and kill this thread
      Avoid race where PCB is freed before t->pcb is set to NULL
      If this happens, then an unfortuantely timed timer interrupt
      can try to activate the pagedir, but it is now freed memory */
    struct process* pcb_to_free = cur->pcb;
    struct child_process* in_parent = pcb_to_free->in_parent;

    if(pcb_to_free->file_lock != NULL ){
        lock_release(pcb_to_free->file_lock);
    }
    /* 清除fd */
    for(int i = 3; i < MAX_FD_NUM; i++){
        if (pcb_to_free->fdt.using[i] && pcb_to_free->fdt.file_ptr[i] != NULL) {
            file_close(pcb_to_free->fdt.file_ptr[i]);
        }
    }
    /* 如果不是fork的，要释放执行文件的写入权限 */
    if(pcb_to_free->elf != NULL){
        file_close(pcb_to_free->elf);
    }

    cur->pcb = NULL;

    /* 清除该PCB的child_list */
    while (!list_empty(&pcb_to_free->child_list)) {
        struct list_elem* e = list_pop_front(&pcb_to_free->child_list);
        struct child_process* child = list_entry(e, struct child_process, elem);
        free(child);
    }
    /* 可能没有父进程。非空时访问 */
    if(in_parent != NULL){
        in_parent->alive = false;
        /* 父进程一直睡眠到这个进程exit，才被唤醒 */
        if(in_parent->wait_by_parent)
            sema_up(&(in_parent->sema));
    }
    /* 清理user lock & sema */
    for(int i = 0; i < MAX_LOCK_NUM; i++) {
        if(pcb_to_free->userlock[i] != NULL)
            free(pcb_to_free->userlock[i]);
        
        if(pcb_to_free->usersema[i] != NULL)
            free(pcb_to_free->usersema[i]);
    }

    
    free(pcb_to_free);

    intr_disable();
    // list_remove(&thread_current()->allelem);
    // thread_current()->status = THREAD_DYING;
    // list_remove(&cur->allelem);
    // cur->status = THREAD_DYING;
    // schedule();
    // NOT_REACHED();
    //     list_remove(&cur->elem);
    // cur->status = THREAD_DYING;


    thread_exit();
}

pid_t process_fork(void){
    struct thread *t = thread_current();

    // printf("[FORK] Parent '%s' (tid=%d) creating child via fork\n", 
    //        t->pcb->process_name, t->tid);

    struct child_process *child = malloc(sizeof(struct child_process));
    if(child == NULL){
        return TID_ERROR;
    }
    child->wait_by_parent = false;
    child->alive = false;
    child->create_success = false;
    child->exit_status = -1;
    sema_init(&(child->sema),0);
    list_push_back(&(t->pcb->child_list),&(child->elem));

    tid_t tid = thread_create(t->pcb->process_name,PRI_DEFAULT,start_fork_process,child);
    if(tid == TID_ERROR){
        return TID_ERROR;
    }


    child->pid = tid;


    /* 让父进程进入等待，创建子进程后唤醒父进程，
        不论是否成功，然后初始化child_PCB并返回tid */
    // printf("[FORK]enter sleep,wait for child init\n");
    sema_down(&child->sema);
    //这里醒了，然后判断是不是true
    // printf("[FORK]wake up from child:%d\n",child->pid);
    if(child->create_success == false){
        list_remove(&child->elem);
        free(child);
        return TID_ERROR;
    }
    return tid;
}
static void start_fork_process(struct child_process *chpcb){
    // printf("[START]enter\n");
    struct thread* t = thread_current();
    bool success = false, pcb_success = false;

    struct process* new_pcb = malloc(sizeof(struct process));
    if(new_pcb == NULL){
        goto fail;
    }
    pcb_success = true;

    memset(new_pcb,0,sizeof(struct process));
    t->pcb = new_pcb;
    t->pcb->pagedir = pagedir_create();

    if(t->pcb->pagedir == NULL){
        goto fail;
    }
    t->pcb->main_thread = t;
    memcpy(t->pcb->process_name,t->name,sizeof(t->pcb->process_name));
    /* fork的进程没有elf */
    t->pcb->elf = NULL;
    list_init(&(t->pcb->child_list));
    list_init(&(t->pcb->multi_thread));

    if (t->parent == NULL || t->parent->pcb == NULL) {
        goto fail;
    }
    /* 复制父进程的fd */
    struct file_descript_table *parent_fdt,*child_fdt;
    parent_fdt = &t->parent->pcb->fdt;
    child_fdt = &t->pcb->fdt;
    memset(child_fdt,0,sizeof(t->pcb->fdt));
    for(size_t i = 3; i < MAX_FD_NUM; i++){
        if(parent_fdt->using[i] == true && parent_fdt->file_ptr[i] != NULL){
            struct file* file = file_fork(parent_fdt->file_ptr[i]);
            if(file == NULL){
                // printf("[START]fork fileptr failed\n");
                goto fail;
            }
            child_fdt->using[i] = true;
            child_fdt->file_ptr[i] = file;
        }
    }
    /* 建立与父进程的连接 */
    t->pcb->in_parent = chpcb;
    chpcb->alive = true;
    chpcb->create_success = true;

    success = copy_memory(t->parent->pcb->pagedir,t->pcb->pagedir);
    if(success == false){
        goto fail;
    }
    struct intr_frame if_ = t->parent->pcb->saved_if;
    if_.eax = 0;
    /* 激活子进程的页表 */
    process_activate();

    sema_up(&t->pcb->in_parent->sema);//加载成功释放信号量
    
    asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
    NOT_REACHED();

fail:
    /* pcb申请成功的话，需要释放pcb */
    printf("[FORK]failed\n");
    if(pcb_success){
        /* 关闭file_ptr */
        for(size_t i = 3; i < MAX_FD_NUM; i++){
            if(t->pcb->fdt.using[i] == true && t->pcb->fdt.file_ptr[i] != NULL){
                file_close(t->pcb->fdt.file_ptr[i]);
            }
        }
        /* 设置在父进程中的chpcb，并sema_up */
        if(t->pcb->in_parent != NULL){
            struct child_process* local_in_parent = t->pcb->in_parent;
            local_in_parent->exit_status = -1;
            local_in_parent->alive = false;
            local_in_parent->create_success = false;
            sema_up(&local_in_parent->sema);
        }
        /* 收尾pcb */
        struct process* pcb_to_free = t->pcb;
        t->pcb = NULL;
        if(pcb_to_free->pagedir != NULL)
            pagedir_destroy(pcb_to_free->pagedir);
        free(pcb_to_free);
    }
    thread_exit();//这里没有释放pcb的pd。会造成内存泄漏嘛?-->process_exit?
}
static bool copy_memory(uint32_t* parent,uint32_t* child){
    void* addr = (void*)0;
    void* vpage = NULL;
    bool writable = false;

    for(;addr < PHYS_BASE; addr = (char*)addr + PGSIZE){
        vpage = pagedir_get_page(parent,addr);
        
        if(vpage == NULL){
            continue;
        }
        /* 该物理页不为空，要新申请一页然后memcpy */
        void* new = palloc_get_page(PAL_USER | PAL_ZERO);
        if(new == NULL){
            return false;
        }
        memcpy(new,vpage,PGSIZE);

        writable = pagedir_is_writable(parent,addr);
        
        if(pagedir_set_page(child,addr,new,writable) != true){
            palloc_free_page(new);
            return false;
        }
    }
    return true;
}

/* Sets up the CPU for running user code in the current
   thread. This function is called on every context switch. */
void process_activate(void) {
  struct thread* t = thread_current();

  /* Activate thread's page tables. */
  if (t->pcb != NULL && t->pcb->pagedir != NULL)
    pagedir_activate(t->pcb->pagedir);
  else
    pagedir_activate(NULL);

  /* Set thread's kernel stack for use in processing interrupts.
     This does nothing if this is not a user process. */
  tss_update();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr {
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr {
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking tsb. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary tsb. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack(void** esp);
static bool validate_segment(const struct Elf32_Phdr*, struct file*);
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load(struct pass_args* arg, void (**eip)(void), void** esp) {

  const char* file_name = arg->argv[0];

  struct thread* t = thread_current();
  struct Elf32_Ehdr ehdr;
  struct file* file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pcb->pagedir = pagedir_create();
  if (t->pcb->pagedir == NULL)
    goto done;
  process_activate();

  /* Open executable file. */
  lock_acquire(&file_lock);
  file = filesys_open(file_name);
  lock_release(&file_lock);
  if (file == NULL) {
    printf("load: %s: open failed\n", file_name);
    goto done;
  }
  file_deny_write(file);
  t->pcb->elf = file;

  /* Read and verify executable header. */
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||
      memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 3 ||
      ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024) {
    printf("load: %s: error loading executable\n", file_name);
    goto done;
  }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) {
    struct Elf32_Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length(file))
      goto done;
    file_seek(file, file_ofs);

    if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
      goto done;
    file_ofs += sizeof phdr;
    switch (phdr.p_type) {
      case PT_NULL:
      case PT_NOTE:
      case PT_PHDR:
      case PT_STACK:
      default:
        /* Ignore this segment. */
        break;
      case PT_DYNAMIC:
      case PT_INTERP:
      case PT_SHLIB:
        goto done;
      case PT_LOAD:
        if (validate_segment(&phdr, file)) {
          bool writable = (phdr.p_flags & PF_W) != 0;
          uint32_t file_page = phdr.p_offset & ~PGMASK;
          uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
          uint32_t page_offset = phdr.p_vaddr & PGMASK;
          uint32_t read_bytes, zero_bytes;
          if (phdr.p_filesz > 0) {
            /* Normal segment.
                     Read initial part from disk and zero the rest. */
            read_bytes = page_offset + phdr.p_filesz;
            zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
          } else {
            /* Entirely zero.
                     Don't read anything from disk. */
            read_bytes = 0;
            zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
          }
          if (!load_segment(file, file_page, (void*)mem_page, read_bytes, zero_bytes, writable))
            goto done;
        } else
          goto done;
        break;
    }
  }

  /* Set up stack. */
  if (!setup_stack(esp))
    goto done;

/*   Address         Name         Data        Type
    0xbffffffc   argv[3][...]    bar\0       char[4]
    0xbffffff8   argv[2][...]    foo\0       char[4]
    0xbffffff5   argv[1][...]    -l\0        char[3]
    0xbfffffed   argv[0][...]    /bin/ls\0   char[8]
    0xbfffffec   stack-align       0         uint8_t
    0xbfffffe8   argv[4]           0         char *   --> NULL
    0xbfffffe4   argv[3]        0xbffffffc   char *
    0xbfffffe0   argv[2]        0xbffffff8   char *
    0xbfffffdc   argv[1]        0xbffffff5   char *
    0xbfffffd8   argv[0]        0xbfffffed   char *
    0xbfffffd4   argv           0xbfffffd8   char **
    0xbfffffd0   argc              4         int
    0xbfffffcc   return address    0         void (*) ()
*/

    void *new_esp = *esp;
    char* arg_ptrs[MAX_ARGC]; //如果不用固定数组，goto会报错

    // 压入参数字符串内容
    for(int i = arg->argc - 1;i >= 0; i--){
        size_t arglen = strlen(arg->argv[i]) + 1;
        new_esp -= arglen;//手动压栈，高地址在上，先减下去，再把这部分填充为argv的数据
        memcpy(new_esp,arg->argv[i],arglen);
        arg_ptrs[i] = new_esp;//记录这个参数的地址（用于后面传递argv）
    }
    
    /* 要让argc的位置是16字节对齐的，total = argv[]s + null + argv[][] + argc */
    size_t total = (arg->argc+1) * sizeof(char*) + sizeof(char**) + sizeof(int);
    void* align = (void*)((char*)new_esp - total);
    align = (void*)((uintptr_t)align & ~0xf);
    new_esp = (char*)align + total;

    /* 压入 argv 字符串指针数组 */
    new_esp = (void*)((char*)new_esp - sizeof(char*));
    *(char**)new_esp = NULL; // argv[argc] = NULL
    for (int i = arg->argc-1; i >= 0; i--){
        new_esp = (void*)((char*)new_esp - sizeof(char*));
        *(char**)new_esp = arg_ptrs[i];
    }
    
    /*  压入 argv入口 和 argc */
    char** argv_on_stack = (char**)new_esp;//这时候指向argv数组的起始地址（二维指针）
    new_esp = (void*)((char*)new_esp - sizeof(char**));
    *(char***)new_esp = argv_on_stack;//argv

    new_esp = (void*)((char*)new_esp - sizeof(int));
    *(int*)new_esp = arg->argc;

    /* 压入0作为返回值 */
    new_esp = (void*)((char*)new_esp - sizeof(void*));
    *(void**)new_esp = 0; // 或 NULL
    /* 更新 if_.esp */
    *esp = new_esp;
    /* Start address. */
    *eip = (void (*)(void))ehdr.e_entry;
    // hex_dump(0, *esp, 128, true);

    success = true;

    return success;

done:
  /* We arrive here whether the load is successful or not. */
  file_close(file);
  return success;
}

/* load() helpers. */

static bool install_page(void* upage, void* kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Elf32_Phdr* phdr, struct file* file) {
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off)file_length(file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr((void*)phdr->p_vaddr))
    return false;
  if (!is_user_vaddr((void*)(phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* 从文件 FILE 中偏移量为 OFS 的位置加载一个段，地址为UPAGE。
   总共初始化 READ_BYTES + ZERO_BYTES 字节的虚拟内存，
   具体如下：
   - 必须从文件 FILE 中偏移量为 OFS 的位置读取 UPAGE 处的 READ_BYTES 字节。
   - 必须将 UPAGE + READ_BYTES 处的 ZERO_BYTES 字节清零。
   如果 WRITABLE 为 true，则此函数初始化的页面必须对用户进程可写；否则为只读。
   如果成功，则返回 true；如果发生内存分配错误或磁盘读取错误，则返回 false。 */
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable) {
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  file_seek(file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) {
    /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* Get a page of memory. */
    uint8_t* kpage = palloc_get_page(PAL_USER);
    if (kpage == NULL)
      return false;

    /* Load this page. */
    if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes) {
      palloc_free_page(kpage);
      return false;
    }
    memset(kpage + page_read_bytes, 0, page_zero_bytes);

    /* Add the page to the process's address space. */
    if (!install_page(upage, kpage, writable)) {
      palloc_free_page(kpage);
      return false;
    }

    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
  }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool setup_stack(void** esp) {
  uint8_t* kpage;
  bool success = false;

  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL) {
      success = install_page(((uint8_t*)PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
         *esp = PHYS_BASE;
      else
         palloc_free_page(kpage);
  }
  return success;
}

/* 将用户虚拟地址 UPAGE 到内核虚拟地址 KPAGE 的映射添加到页表中。
   如果 WRITABLE 为真，则用户进程可以修改该页；否则，该页为只读。
   UPAGE 必须尚未被映射。KPAGE 应该是从用户池中获取的页，
   可通过 palloc_get_page() 获取。
   成功时返回 true，如果 UPAGE 已被映射或内存分配失败，则返回 false。 */
static bool install_page(void* upage, void* kpage, bool writable) {
  struct thread* t = thread_current();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page(t->pcb->pagedir, upage) == NULL &&
          pagedir_set_page(t->pcb->pagedir, upage, kpage, writable));
}

/* Returns true if t is the main thread of the process p */
bool is_main_thread(struct thread* t, struct process* p) { return p->main_thread == t; }

/* Gets the PID of a process */
pid_t get_pid(struct process* p) { return (pid_t)p->main_thread->tid; }

uint8_t* find_stack_addr(void){
    uint8_t* addr = (uint8_t*)PHYS_BASE - PGSIZE;
    struct process* p = thread_current()->pcb;
    struct thread* t = NULL;

    if (p == NULL || p->pagedir == NULL) {
        printf("pd is NULL!\n");
        return NULL;
    }
    while(addr > (uint8_t*)0x08048000){
        bool occupied = false;

        enum intr_level old_level = intr_disable();
        /* 遍历当前threads，查看地址是否已经被占用 */
        for(struct list_elem* e = list_begin(&p->multi_thread); e != list_end(&p->multi_thread);
                e = list_next(e))
        {
            struct thread_status_block* tsb = list_entry(e, struct thread_status_block,pcb_elem);
            /* 对于已经完成的tsb，tsb->th已经被释放了，不能访问到user_stack了 */
            if(tsb->finished == true){ continue; }
            t = tsb->th;
            
            if( t->user_stack == addr){
                occupied = true;
                break;
            }
        }
        intr_set_level(old_level);

        if(occupied == false && pagedir_get_page(p->pagedir,addr) == NULL){
            // printf("find addr:%p\n",addr);
            return addr;
        }
        addr -= PGSIZE;
    }
    printf("can't find valuable addr\n");
    return NULL;
}
/* 为线程创建一个新栈并设置其参数。将线程的入口点存储到 *EIP，并将初始栈指针存储到 *ESP。
  如果操作失败，则处理所有清理工作。成功返回 true，否则返回 false。 */
bool setup_thread(void (**eip)(void) , void** esp ) {
    uint8_t* kpage;
    uint8_t* stack_addr;
    bool success = false;

    /* 申请一块地址，把这个地址install到合适的位置 */
    kpage = palloc_get_page(PAL_USER | PAL_ZERO);
    if (kpage != NULL) {
        lock_acquire(&pthread_lock);

        stack_addr = find_stack_addr();

        if(stack_addr == NULL){
            printf("get empty stackaddr\n");
            palloc_free_page(kpage);
            lock_release(&pthread_lock);
            return success;
        }
        
        success = install_page(((uint8_t*)stack_addr), kpage, true);
        if (success){
            thread_current()->user_stack = stack_addr;
            *esp = stack_addr + PGSIZE;//栈顶
        }
        else
            palloc_free_page(kpage);

        lock_release(&pthread_lock);
    }
    return success;
}

struct exec_arg{
    stub_fun sf ;
    pthread_fun tf ; 
    void* arg;
    bool success;//暂未使用到
    struct semaphore sema;
    struct process* p;
};
/* 启动一个新线程，该线程使用新的用户栈运行 SF，
  并接受TF 和 ARG 作为用户栈上的参数。
  这个新线程可能在 pthread_execute() 返回之前被调度（甚至可能退出）。
  返回新线程的 TID，如果线程无法正确创建，则返回 TID_ERROR。
  并且应该类似于 process_execute()。
*/
tid_t pthread_execute(stub_fun sf , pthread_fun tf , const void* arg ) {
    struct exec_arg* thread_arg = calloc(sizeof(struct exec_arg),1);
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
    struct exec_arg* exec = (struct exec_arg*)exec_;
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


/* ====================  user sync part ====================  */
bool user_lock_init(lock_t* lock) {
    if(lock == NULL)return false;

    struct process *p = thread_current()->pcb;

    lock_acquire(&user_sema_lock);
    for(int idx = 0; idx < MAX_LOCK_NUM; idx++){
        if(p->userlock[idx] == NULL){
            struct lock* new = malloc(sizeof(struct lock));
            if(new == NULL){
                lock_release(&user_sema_lock);
                return false;
            }
            lock_init(new);

            p->userlock[idx] = new;
            *lock = (lock_t)idx;
            lock_release(&user_sema_lock);
            return true;
        }
    }
    lock_release(&user_sema_lock);
    return false;
}

bool user_lock_acquire(lock_t* lock) { 
    if(lock == NULL || *lock >= MAX_LOCK_NUM || *lock < 0)return false;

    struct thread *t = thread_current();
    struct process *p = t->pcb;
    if(p->userlock[*lock] == NULL || p->userlock[*lock]->holder == t){
        return false;
    }
    lock_acquire(p->userlock[*lock]);
    return true;
}

bool user_lock_release(lock_t* lock) {
    if(lock == NULL || *lock >= MAX_LOCK_NUM || *lock < 0)return false;

    struct thread *t = thread_current();
    struct process *p = t->pcb;

    if(p->userlock[*lock] == NULL || p->userlock[*lock]->holder != t){
        return false;
    }
    lock_release(p->userlock[*lock]);
    return true;
}

bool user_sema_init(sema_t* sema, int val) {
    //这里是做赋值，不用判断
    if(sema == NULL || val < 0){return false;}

    struct process *p = thread_current()->pcb;
    
    lock_acquire(&user_sema_lock);
    for(int idx = 0; idx < MAX_LOCK_NUM; idx++){
        if(p->usersema[idx] == NULL){
            struct semaphore* new = malloc(sizeof(struct semaphore));
            if(new == NULL){
                lock_release(&user_sema_lock);  
                return false;
            }
            sema_init(new,val);

            p->usersema[idx] = new;
            *sema = (sema_t)idx;
            lock_release(&user_sema_lock);
            return true;
        }
    }
    lock_release(&user_sema_lock);
    return false;
}
bool user_sema_up(sema_t* sema) {
    if(sema == NULL || *sema >= MAX_LOCK_NUM || *sema < 0){return false;}

    struct thread *t = thread_current();
    struct process *p = t->pcb;
    if(p->usersema[*sema] == NULL){
        return false;
    }
    sema_up(p->usersema[*sema]);
    return true;
}
bool user_sema_down(sema_t* sema) {
    if(sema == NULL || *sema >= MAX_LOCK_NUM || *sema < 0){return false;}

    struct thread *t = thread_current();
    struct process *p = t->pcb;
    if(*sema >= MAX_LOCK_NUM || p->usersema[*sema] == NULL){
        return false;
    }
    sema_down(p->usersema[*sema]);
    return true;
}

/* ====================  helper ==================== */
static void release_holding_lock(struct list* list){
    while(!list_empty(list)) {
        struct list_elem* e = list_pop_front(list);
        struct lock* lock = list_entry(e,struct lock,elem);
        lock_release(lock);
    }
}