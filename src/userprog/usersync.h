
#ifndef __USER_SYNC_H__
#define __USER_SYNC_H__

#include <stdbool.h>

/* Synchronization Types */
typedef char lock_t;
typedef char sema_t;
bool user_lock_init(lock_t* lock);
bool user_lock_acquire(lock_t* lock);
bool user_lock_release(lock_t* lock);
bool user_sema_init(sema_t* sema, int val);
bool user_sema_up(sema_t* sema);
bool user_sema_down(sema_t* sema);

#endif

