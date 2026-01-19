#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"

#include <string.h>
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"
#include "filesys/inode.h"
#include "filesys/free-map.h"

static void syscall_handler(struct intr_frame*);

static void check_valid_num(uint32_t* args);
static void check_valid_str(const char* str);
static void check_valid_buffer(const void* buffer, size_t size);


void syscall_init(void) { 
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); 
}

void syscall_exit(int status);
static uint32_t syscall_exec(const char* file_name);
static bool syscall_create(const char *file, unsigned initial_size);
static bool syscall_remove(const char *file);
static int syscall_open(const char *file);
static int syscall_filesize(int fd);
static int syscall_read(int fd, void* buffer, unsigned size);
static uint32_t syscall_wait(pid_t pid);
static int syscall_write(int fd, void* buffer, size_t size);
static void syscall_seek(int fd,unsigned position);
static int syscall_tell(int fd);
static void syscall_close(int fd);
static pid_t syscall_fork(struct intr_frame* f);
static tid_t syscall_pt_create(stub_fun sfun, pthread_fun tfun, const void* arg);
static void syscall_pt_exit(void);
static tid_t syscall_pt_join(tid_t tid);
static bool syscall_lock_init(lock_t* lock);
static bool syscall_lock_acquire(lock_t *lock);
static bool syscall_lock_release(lock_t *lock);
static bool syscall_sema_init(sema_t* sema, int val);
static bool syscall_sema_up(sema_t* sema);
static bool syscall_sema_down(sema_t* sema);
static tid_t syscall_get_tid(void);
static bool syscall_mkdir(const char* name);
static bool syscall_chdir(const char* name);
// static bool syscall_readdir(int fd, char name[READDIR_MAX_LEN + 1]);
static bool syscall_readdir(int fd, char* name);
static bool syscall_isdir(int fd);
static int syscall_inumber(int fd);
//arg[0]是调用号，其余是参数
static void syscall_handler(struct intr_frame* f UNUSED) {
    //调用者的堆栈指针可以通过传递给它的 struct intr_frame 的 esp 成员访问。指针数组
    uint32_t *args = ((uint32_t*)f->esp);//32bit width

    //   printf("arg0 = %d, arg2 = %s\n",args[0],(char*)args[2]);
    check_valid_num(&args[0]);//检查栈顶指针是否有问题

    switch(args[0]){
        case SYS_HALT:
            shutdown_power_off();
            break;
            
        case SYS_EXIT:
            check_valid_num(&args[1]);
            syscall_exit(args[1]);
            break;
        
        case SYS_EXEC:
            check_valid_str((char*)args[1]);
            f->eax = syscall_exec((char*)args[1]);
            break;
        
        case SYS_WAIT:
            check_valid_num(&args[1]);
            f->eax = syscall_wait(args[1]);
            break;
        
        case SYS_CREATE:
            check_valid_str((char*)args[1]);
            check_valid_num(&args[2]);
            f->eax = syscall_create((char*)args[1],args[2]);
            break;
        
        case SYS_REMOVE:
            check_valid_str((char*)args[1]);
            f->eax = syscall_remove((char*)args[1]);
            break;
        
        case SYS_OPEN:
            check_valid_str((char*)args[1]);
            f->eax = syscall_open((char*)args[1]);
            break;

        case SYS_FILESIZE:
            check_valid_num(&args[1]);
            f->eax = syscall_filesize(args[1]);
            break;
        
        case SYS_READ:
            check_valid_num(&args[1]);
            check_valid_num(&args[3]);
            check_valid_buffer((void*)args[2],args[3]);
            f->eax = syscall_read(args[1],(void*)args[2],args[3]);
            break;

        case SYS_WRITE:
            check_valid_num(&args[1]);
            check_valid_num(&args[3]);
            check_valid_buffer((void*)args[2],args[3]);
            f->eax = syscall_write((int)args[1],(void*)args[2],(size_t)args[3]);
            break;

        case SYS_SEEK:
            check_valid_num(&args[1]);
            check_valid_num(&args[2]);
            syscall_seek(args[1],args[2]);
            break;

        case SYS_TELL:
            check_valid_num(&args[1]);
            f->eax = syscall_tell(args[1]);
            break;

        case SYS_CLOSE:
            check_valid_num(&args[1]);
            syscall_close(args[1]);
            break;
        
        case SYS_PRACTICE:
            check_valid_num(&args[1]);
            f->eax = args[1] + 1;
            break;

        case SYS_FORK:
            f->eax = syscall_fork(f);
            break;

        case SYS_PT_CREATE:
            f->eax = syscall_pt_create((stub_fun)args[1],(pthread_fun)args[2],(void*)args[3]);
            break;
        
        case SYS_PT_EXIT:
            syscall_pt_exit();
            break;

        case SYS_PT_JOIN:
            f->eax = syscall_pt_join(args[1]);
            break;

        case SYS_LOCK_INIT:
            // check_valid_num(args[1]);
            f->eax = syscall_lock_init((lock_t*)args[1]);
            break;

        case SYS_LOCK_ACQUIRE:
            f->eax = syscall_lock_acquire((lock_t*)args[1]);
            break;

        case SYS_LOCK_RELEASE:
            f->eax = syscall_lock_release((lock_t*)args[1]);
            break;

        case SYS_SEMA_INIT:
            f->eax = syscall_sema_init((sema_t*)args[1],args[2]);
            break;

        case SYS_SEMA_DOWN:
            f->eax = syscall_sema_down((sema_t*)args[1]);
            break;

        case SYS_SEMA_UP:
            f->eax = syscall_sema_up((sema_t*)args[1]);
            break;

        case SYS_GET_TID:
            f->eax = syscall_get_tid();
            break;

            
        case SYS_CHDIR:
            f->eax = syscall_chdir((char*)args[1]);
            break;

        case SYS_MKDIR:
            f->eax = syscall_mkdir((char*)args[1]);
            break;
        case SYS_READDIR:
            f->eax = syscall_readdir((int)args[1],(char*)args[2]);
            break;
        case SYS_ISDIR :
            f->eax = syscall_isdir((int)args[1]);
            break;
        case SYS_INUMBER :
            PANIC("syscall not imple2\n");
    }
}

/* 验证num是否在用户空间、指针指向的地址是否是已分配内存的 */
static void check_valid_num(uint32_t* num){
    struct thread *t = thread_current();

    if(num == NULL || pagedir_get_page(t->pcb->pagedir,num) == NULL)
    {//pgdir_getpage已经检查了是否在uaddr
        syscall_exit(-1);
    }
    void* this_byte = (void*)num;
    for(int i = 1; i <= 3; i++){
        this_byte = (void*)((char*)this_byte + i);
        if(num == NULL || pagedir_get_page(t->pcb->pagedir,this_byte) == NULL)
        {//pgdir_getpage已经检查了是否在uaddr
            syscall_exit(-1);
        }
    }
}
static void check_valid_str(const char* str){
    struct thread *t = thread_current();
    if(str == NULL){
        syscall_exit(-1);
    }
    if(pagedir_get_page(t->pcb->pagedir,str) == NULL){
        syscall_exit(-1);
    }

    char* p = str;
    int cnt = 0;
    
    while(cnt < 1024){
        if(pagedir_get_page(t->pcb->pagedir,p) == NULL){
            syscall_exit(-1);
        }
        if(*p == '\0')return;//找到结尾了，不用继续了
        p++;
        cnt++;
    }
    if(cnt >= 1024){
        syscall_exit(-1);
    }
}
static void check_valid_buffer(const void* buffer, size_t size){
    if(buffer == NULL){
        syscall_exit(-1);
    }

    if(size == 0)return;

    struct thread *t = thread_current();

    if(pagedir_get_page(t->pcb->pagedir,buffer) == NULL){
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
void syscall_exit(int status){
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, status);

    struct thread* cur = thread_current();
    /* 设置退出码，供父进程读取 */
    if (cur->pcb->in_parent != NULL) {
        cur->pcb->in_parent->exit_status = status;
    }
    process_exit();//程序运行到这里就结束了，不会有返回值
}
static uint32_t syscall_exec(const char* file_name){
    return process_execute(file_name);
}
static bool syscall_create(const char *file, unsigned initial_size){
    if (strlen(file) > 256) return false;
    return filesys_create(file,initial_size);
}
static bool syscall_remove(const char *file){
    return  filesys_remove(file);
}
static int syscall_open(const char *file){
    struct file* ptr = NULL;
    ptr = filesys_open(file);

    if(ptr == NULL){ return -1; }

    //应该从pcb的fd进行对比，找到在不在，然后更新
    struct file_descript_table* entry = &(thread_current()->pcb->fdt);
    
    int16_t idx_unused = -1;
    /* 不需要管0(标准输入)，1(标准输出)，2(标准错误) */
    for(size_t i = 3; i < MAX_FD_NUM; i++){
        /* 先判断有没有在使用 */
        if(entry->using[i] == true){
            if(ptr == entry->file_ptr[i]){ return i; }
        }else{
            if(idx_unused == -1){ idx_unused = i; }
        }
    }
    /* 没有return，没找到对应的 */
    if(idx_unused == -1){ return -1; }
    /* 没满 */
    entry->using[idx_unused] = true;
    entry->file_ptr[idx_unused] = ptr;

    return idx_unused;
}
static int syscall_filesize(int fd){
    struct process* p = thread_current()->pcb;
    /* 检查是否在使用 */
    if(p->fdt.using[fd] == false){
        return -1;
    }
    int size = file_length(p->fdt.file_ptr[fd]);
    return size;
}
static int syscall_read(int fd, void* buffer, unsigned size){
    /* 范围检查 */
    if(fd < 0 || fd >= MAX_FD_NUM){
        return -1;
    }

    struct process* p = thread_current()->pcb;
    /* 检查是否存在 */
    if(p->fdt.using[fd] == false){
        return -1;
    }
    /* 从文件中读取 */
    int cur_read = 0;
    if(fd > 2){
        cur_read = file_read(p->fdt.file_ptr[fd],buffer,size);
        return cur_read;
    }
    /* 从标准输入读取 */
    if(fd == STDIN_FILENO){
        while((unsigned)cur_read < size){
            ((char*)buffer)[cur_read++] = input_getc();
        }
        /* 从0开始计数，直接返回cur即可 */
        return cur_read;
    }
}
static uint32_t syscall_wait(pid_t pid){
    return process_wait(pid);
}
static int syscall_write(int fd, void* buffer, size_t size){
    /* 范围检查 */
    if(fd < 0 || fd >= MAX_FD_NUM || fd == STDIN_FILENO){
        return -1;
    }

    if(fd == STDOUT_FILENO){
        if(size <= 512){
            putbuf(buffer,size);
            return size;
        }
        /* 太长的要拆分成多个块 */
        int cur_size = 0;
        while(cur_size < size){
            if(size - cur_size > 512){
                putbuf(buffer,512);
                cur_size += 512;
                buffer = (char*)buffer + 512;
            }else{
                int less = size - cur_size;
                putbuf(buffer,less);
                cur_size += less;
            }
        }
        return cur_size; 
    }

    if(fd > 2){
        struct process* p = thread_current()->pcb;
        if(p->fdt.using[fd] == false){ 
            // printf("fd error!\n");
            return -1; 
        }
        // if (syscall_isdir(fd)) { return -1; }
        int ret = file_write(p->fdt.file_ptr[fd],buffer,size);
        return ret;
    }
}
static void syscall_seek(int fd,unsigned position){
    if(fd <= 2 || fd >= MAX_FD_NUM){ return; }
    struct process* p = thread_current()->pcb;
    if(p->fdt.using[fd] == false){ return ; }
    file_seek(p->fdt.file_ptr[fd],position);
}
static int syscall_tell(int fd){
    if(fd <= 2 || fd >= MAX_FD_NUM){
        return -1;
    }
    struct process* p = thread_current()->pcb;
        if(p->fdt.using[fd] == false){
            return -1;
        }
    int ret = file_tell(p->fdt.file_ptr[fd]);
    return ret;
}
static void syscall_close(int fd){
    if(fd <= 2 || fd >= MAX_FD_NUM){
        return;
    }
    struct process* p = thread_current()->pcb;
    if(p->fdt.using[fd] == true){
        file_close(p->fdt.file_ptr[fd]);
        p->fdt.using[fd] = false;
        p->fdt.file_ptr[fd] = NULL;
    }
}
static pid_t syscall_fork(struct intr_frame* f){
    struct thread* t = thread_current();
    /* 保存父进程的寄存器状态，用于模拟中断 */
    t->pcb->saved_if = *f;
    return process_fork();
}
static tid_t syscall_pt_create(stub_fun sfun, pthread_fun tfun, const void* arg){
    return pthread_execute(sfun,tfun,arg);
}
static void syscall_pt_exit(void){
    pthread_exit();
}
static tid_t syscall_pt_join(tid_t tid){
    return pthread_join(tid);
}
static bool syscall_lock_init(lock_t* lock) {
    return user_lock_init(lock);
}
static bool syscall_lock_acquire(lock_t *lock){
    return user_lock_acquire(lock);
}
static bool syscall_lock_release(lock_t *lock){
    return user_lock_release(lock);
}
static bool syscall_sema_init(sema_t* sema, int val){
    return user_sema_init(sema,val);
}
static bool syscall_sema_up(sema_t* sema){
    return user_sema_up(sema);
}
static bool syscall_sema_down(sema_t* sema){
    return user_sema_down(sema);
}
static tid_t syscall_get_tid(void){
    return thread_tid();
}
static bool syscall_mkdir(const char* name) {
    /* 建立一个目录 */
    block_sector_t sector;
    bool success = false;
    if (free_map_allocate(1, &sector)) {
        success = dir_create(sector,16);
    }

    if (success) { 
        struct process* p = thread_current()->pcb;
        /* 把目录写到父目录里 */
        success = dir_add(p->cwd, name, sector);
    }

    return success;
}
static bool syscall_chdir(const char* name) {
    struct inode* inode = NULL;
    bool success = false;
    /* 获取当前目录 */
    struct process* p = thread_current()->pcb;

    struct dir* cwd = p->cwd;

    success = dir_lookup(cwd, name, &inode);

    if (success) {
        struct dir* new = dir_open(inode);
        if (new != NULL) {
            p->cwd = new;
        } else {
            success = false;
        }
    }

    return success;
}
static bool syscall_readdir(int fd, char* name) {
    PANIC("syscall not imple\n");
}
static bool syscall_isdir(int fd) {
    /* 范围检查 */
    if(fd < 2 || fd >= MAX_FD_NUM) { return -1; }

    struct process* p = thread_current()->pcb;
    /* 检查是否存在 */
    if(p->fdt.using[fd] == false) { return -1; }
    return file_is_dir(p->fdt.file_ptr[fd]);
}
static int syscall_inumber(int fd);