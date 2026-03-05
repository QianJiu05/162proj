
#include "userprog/usersync.h"
#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/malloc.h"

#include "userprog/syscall.h"

/* ====================  user sync part ====================  */
bool user_lock_init(lock_t* lock) {
    if(lock == NULL)return false;

    struct process *p = thread_current()->pcb;

    lock_acquire(&p->user_sync_lock);
    for(int idx = 0; idx < MAX_LOCK_NUM; idx++){
        if(p->userlock[idx] == NULL){
            struct lock* new = malloc(sizeof(struct lock));
            if(new == NULL){
                lock_release(&p->user_sync_lock);
                return false;
            }
            lock_init(new);

            p->userlock[idx] = new;
            *lock = (lock_t)idx;
            lock_release(&p->user_sync_lock);
            return true;
        }
    }
    lock_release(&p->user_sync_lock);
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
    
    lock_acquire(&p->user_sync_lock);
    for(int idx = 0; idx < MAX_LOCK_NUM; idx++){
        if(p->usersema[idx] == NULL){
            struct semaphore* new = malloc(sizeof(struct semaphore));
            if(new == NULL){
                lock_release(&p->user_sync_lock);  
                return false;
            }
            sema_init(new,val);

            p->usersema[idx] = new;
            *sema = (sema_t)idx;
            lock_release(&p->user_sync_lock);
            return true;
        }
    }
    lock_release(&p->user_sync_lock);
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