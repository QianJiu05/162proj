#include "devices/timer.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include "devices/pit.h"
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "threads/thread.h"

#include <list.h>

/* See [8254] for hardware details of the 8254 timer chip. */

#if TIMER_FREQ < 19
#error 8254 timer requires TIMER_FREQ >= 19
#endif
#if TIMER_FREQ > 1000
#error TIMER_FREQ <= 1000 recommended
#endif

/* Number of timer ticks since OS booted.
int64_t max is 2^63-1, roundly 9.22*10^18
按照一般FREQ为100hz来算需要2.9亿年才会溢出 */
static int64_t ticks;

struct list sleep_list;
// struct lock lock_for_list;
struct sleep_elem{
    int64_t target_tick;    /* 目标睡眠时间 */
    struct semaphore sema;  /* 信号量用于睡眠 */
    struct list_elem elem;
};
/* Number of loops per timer tick.
   Initialized by timer_calibrate(). */
static unsigned loops_per_tick;

static intr_handler_func timer_interrupt;
static bool too_many_loops(unsigned loops);
static void busy_wait(int64_t loops);
static void real_time_sleep(int64_t num, int32_t denom);
static void real_time_delay(int64_t num, int32_t denom);

/* Sets up the timer to interrupt TIMER_FREQ times per second,
   and registers the corresponding interrupt. */
void timer_init(void) {
    pit_configure_channel(0, 2, TIMER_FREQ);
    intr_register_ext(0x20, timer_interrupt, "8254 Timer");
    list_init(&sleep_list);
}

/* 校准 loops_per_tick, used to implement brief delays. */
void timer_calibrate(void) {
  unsigned high_bit, test_bit;

  ASSERT(intr_get_level() == INTR_ON);
  printf("Calibrating timer...  ");

  /* 将loops_per_tick近似为小于一个定时器周期内的最大二的幂。 */
  loops_per_tick = 1u << 10;//假设至少能在一个tick内跑完1024次
  while (!too_many_loops(loops_per_tick << 1)) {
    loops_per_tick <<= 1;//翻倍跑试试
    ASSERT(loops_per_tick != 0);
  }

  /* Refine the next 8 bits of loops_per_tick. */
  high_bit = loops_per_tick;
  for (test_bit = high_bit >> 1; test_bit != high_bit >> 10; test_bit >>= 1)
    if (!too_many_loops(loops_per_tick | test_bit))
      loops_per_tick |= test_bit;

  printf("%'" PRIu64 " loops/s.\n", (uint64_t)loops_per_tick * TIMER_FREQ);
}

/* Returns the number of timer ticks since the OS booted. */
int64_t timer_ticks(void) {
  enum intr_level old_level = intr_disable();
  int64_t t = ticks;
  intr_set_level(old_level);
  return t;
}

/* Returns the number of timer ticks elapsed since THEN, which
   should be a value once returned by timer_ticks(). */
int64_t timer_elapsed(int64_t then) { return timer_ticks() - then; }

/* compare helper tick应该从小到大排序*/
static bool tick_compare(const struct list_elem* a, const struct list_elem* b, void* aux UNUSED){
   struct sleep_elem* cur_a = list_entry(a,struct sleep_elem,elem);
   struct sleep_elem* cur_b = list_entry(b,struct sleep_elem,elem);
   return cur_a->target_tick < cur_b->target_tick;
}
/* Sleeps for approximately TICKS timer ticks.  Interrupts must
   be turned on. */
void timer_sleep(int64_t ticks) {
    int64_t start = timer_ticks();

    ASSERT(intr_get_level() == INTR_ON);

    if(ticks <= 0)return;
    int64_t target = start + ticks;

    /* 局部变量，在线程的栈上分配 */
    struct sleep_elem new;
    new.target_tick = target;
   //  printf("taget = %d\n",target);
    sema_init(&new.sema,0);

    /* 关中断 */
    enum intr_level old_level = intr_disable();
    list_insert_ordered(&sleep_list,&new.elem,tick_compare,NULL);

/* FOR DEBUG. INSERT CORRECT 
tick = 329, tick = 339, tick = 349, tick = 359, tick = 369, tick = 525*/
      // printf("==============tick insert==============\n");
      // struct sleep_elem* cur = NULL;
      // struct list_elem* e = NULL;
      // for(e = list_begin(&sleep_list);e != list_end(&sleep_list);
      //         e = list_next(e))
      // {
      //     cur = list_entry(e,struct sleep_elem,elem);
      //     printf("tick = %d, ",cur->target_tick);
      // }
      // printf("\n");

    sema_down(&new.sema);
    /* 醒了之后开中断，中断仅作用于当前线程，
    睡眠时发生了线程切换，切到了其他线程 */
    intr_set_level(old_level);

          

}

/* Sleeps for approximately MS milliseconds.  Interrupts must be
   turned on. */
void timer_msleep(int64_t ms) { real_time_sleep(ms, 1000); }

/* Sleeps for approximately US microseconds.  Interrupts must be
   turned on. */
void timer_usleep(int64_t us) { real_time_sleep(us, 1000 * 1000); }

/* Sleeps for approximately NS nanoseconds.  Interrupts must be
   turned on. */
void timer_nsleep(int64_t ns) { real_time_sleep(ns, 1000 * 1000 * 1000); }

/* Busy-waits for approximately MS milliseconds.  Interrupts need
   not be turned on.

   Busy waiting wastes CPU cycles, and busy waiting with
   interrupts off for the interval between timer ticks or longer
   will cause timer ticks to be lost.  Thus, use timer_msleep()
   instead if interrupts are enabled. */
void timer_mdelay(int64_t ms) { real_time_delay(ms, 1000); }

/* Sleeps for approximately US microseconds.  Interrupts need not
   be turned on.

   Busy waiting wastes CPU cycles, and busy waiting with
   interrupts off for the interval between timer ticks or longer
   will cause timer ticks to be lost.  Thus, use timer_usleep()
   instead if interrupts are enabled. */
void timer_udelay(int64_t us) { real_time_delay(us, 1000 * 1000); }

/* Sleeps execution for approximately NS nanoseconds.  Interrupts
   need not be turned on.

   Busy waiting wastes CPU cycles, and busy waiting with
   interrupts off for the interval between timer ticks or longer
   will cause timer ticks to be lost.  Thus, use timer_nsleep()
   instead if interrupts are enabled.*/
void timer_ndelay(int64_t ns) { real_time_delay(ns, 1000 * 1000 * 1000); }

/* Prints timer statistics. */
void timer_print_stats(void) { printf("Timer: %" PRId64 " ticks\n", timer_ticks()); }

/* Timer interrupt handler. */
static void timer_interrupt(struct intr_frame* args UNUSED) {
  ticks++;
  thread_tick();

  if(list_empty(&sleep_list))return;

  struct list_elem* e = list_begin(&sleep_list);
  while(e != list_end(&sleep_list)){
      struct sleep_elem* cur = list_entry(e,struct sleep_elem,elem);
        /* 大了，不用往后找了 */
        if(cur->target_tick <= ticks){
            sema_up(&cur->sema);
            /* list_rm会返回原节点的next节点 */
            e = list_remove(&cur->elem);
        }else{
            break;
        }
  }
}

/* Returns true if LOOPS iterations waits for more than one timer
   tick, otherwise false. */
static bool too_many_loops(unsigned loops) {
  /* Wait for a timer tick. */
  int64_t start = ticks;
  while (ticks == start)
    barrier();

  /* Run LOOPS loops. */
  start = ticks;
  busy_wait(loops);

  /* If the tick count changed, we iterated too long. */
  barrier();
  return start != ticks;
}

/* Iterates through a simple loop LOOPS times, for implementing
   brief delays.

   Marked NO_INLINE because code alignment can significantly
   affect timings, so that if this function was inlined
   differently in different places the results would be difficult
   to predict. */
static void NO_INLINE busy_wait(int64_t loops) {
  while (loops-- > 0)
    barrier();
}

/* Sleep for approximately NUM/DENOM seconds. */
static void real_time_sleep(int64_t num, int32_t denom) {
  /* Convert NUM/DENOM seconds into timer ticks, rounding down.

        (NUM / DENOM) s
     ---------------------- = NUM * TIMER_FREQ / DENOM ticks.
     1 s / TIMER_FREQ ticks
  */
  int64_t ticks = num * TIMER_FREQ / denom;

  ASSERT(intr_get_level() == INTR_ON);
  if (ticks > 0) {
    /* We're waiting for at least one full timer tick.  Use
         timer_sleep() because it will yield the CPU to other
         processes. */
    timer_sleep(ticks);
  } else {
    /* Otherwise, use a busy-wait loop for more accurate
         sub-tick timing. */
    real_time_delay(num, denom);
  }
}

/* Busy-wait for approximately NUM/DENOM seconds. */
static void real_time_delay(int64_t num, int32_t denom) {
  /* Scale the numerator and denominator down by 1000 to avoid
     the possibility of overflow. */
  ASSERT(denom % 1000 == 0);
  busy_wait(loops_per_tick * num / 1000 * TIMER_FREQ / (denom / 1000));
}
