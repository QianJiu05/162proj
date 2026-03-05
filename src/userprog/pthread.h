#ifndef __USERPROG_PTHREAD_H__
#define __USERPROG_PTHREAD_H__

#include "threads/thread.h"
#include <stdint.h>

/* Thread functions (Project 2: Multithreading) */
typedef void (*pthread_fun)(void*);
typedef void (*stub_fun)(pthread_fun, void*);

struct pthread_create_arg{ 
    stub_fun sf ;
    pthread_fun tf ; 
    void* arg;
    bool success;//暂未使用到
    struct semaphore sema;
    struct process* p;
};

tid_t pthread_execute(stub_fun, pthread_fun, const void*);
tid_t pthread_join(tid_t);
void pthread_exit(void);
void pthread_exit_main(void);

#endif