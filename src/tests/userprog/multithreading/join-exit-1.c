/* Main 函数会创建一个新线程，该线程会join到 Main 函数中。
然后，Main 函数调用 pthread_exit() 并唤醒join线程。
Main 函数的 pthread_exit() 会等待所有未join的线程完成。
因此，Main 函数应该等待新创建的线程执行完毕。
之后，Main 函数应该以退出代码 0 优雅地终止进程。 */

#include "tests/lib.h"
#include "tests/main.h"
#include <syscall.h>
#include <pthread.h>

void thread_function(void* arg_);

/* Thread function that tests exit conditions */
void thread_function(void* arg_) {
  int* main_tid = (int*)arg_;
  msg("Thread starting");
  pthread_check_join(*main_tid);
  msg("Thread finished");
}

void test_main(void) {
  msg("Main starting");
  tid_t main_tid = get_tid();
  pthread_check_create(thread_function, &main_tid);
  pthread_exit();
  fail("Should not be here");
}
