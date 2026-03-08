#include "threads/palloc.h"
#include <bitmap.h>
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "threads/loader.h"
#include "threads/synch.h"
#include "threads/vaddr.h"

#include <stdlib.h>
#include "lib/kernel/hash.h"
/* Page allocator.  Hands out memory in page-size (or
   page-multiple) chunks.  See malloc.h for an allocator that
   hands out smaller chunks.

   System memory is divided into two "pools" called the kernel
   and user pools.  The user pool is for user (virtual) memory
   pages, the kernel pool for everything else.  The idea here is
   that the kernel needs to have memory for its own operations
   even if user processes are swapping like mad.

   By default, half of system RAM is given to the kernel pool and
   half to the user pool.  That should be huge overkill for the
   kernel pool, but that's just fine for demonstration purposes. */

/* A memory pool. */
struct pool {
  struct lock lock;        /* Mutual exclusion. */
  struct bitmap* used_map; /* Bitmap of free pages. */
  uint8_t* base;           /* Base of pool. */
};

/* Two pools: one for kernel data, one for user pages. */
static struct pool kernel_pool, user_pool;


struct frame_entry {
   void* page;             /* 物理页面地址 */
   int64_t ref_cnt;        /* 物理页面被多少进程使用 */
   struct hash_elem elem;  /* hash node */
};

struct hash frame_table;

static unsigned frame_hash_func(const struct hash_elem* e, void* aux UNUSED) ;
static bool frame_less_func(const struct hash_elem* a, const struct hash_elem* b,void* aux UNUSED);
void increace_frame_ref(uint32_t* page);
void decreace_frame_ref(uint32_t* page) ;

static void init_pool(struct pool*, void* base, size_t page_cnt, const char* name);
static bool page_from_pool(const struct pool*, void* page);

/* Initializes the page allocator.  At most USER_PAGE_LIMIT
   pages are put into the user pool. */
void palloc_init(size_t user_page_limit) {
  /* Free memory starts at 1 MB and runs to the end of RAM. */
  uint8_t* free_start = ptov(1024 * 1024);
  uint8_t* free_end = ptov(init_ram_pages * PGSIZE);
  size_t free_pages = (free_end - free_start) / PGSIZE;
  size_t user_pages = free_pages / 2;
  size_t kernel_pages;
  if (user_pages > user_page_limit)
    user_pages = user_page_limit;
  kernel_pages = free_pages - user_pages;

  /* Give half of memory to kernel, half to user. */
  init_pool(&kernel_pool, free_start, kernel_pages, "kernel pool");
  init_pool(&user_pool, free_start + kernel_pages * PGSIZE, user_pages, "user pool");
  hash_init(&frame_table, frame_hash_func, frame_less_func, NULL);

}

/* 获取并返回一组 PAGE_CNT 个连续的空闲页。
  如果设置了 PAL_USER，则从用户池获取这些页；
  否则从内核池获取。如果在 FLAGS 中设置了 PAL_ZERO，
  则这些页将被填充为零。如果可用页数过少，
  则返回空指针，除非在 FLAGS 中设置了 PAL_ASSERT，
  这种情况下，内核将发生 panic。 */
void* palloc_get_multiple(enum palloc_flags flags, size_t page_cnt) {
  struct pool* pool = flags & PAL_USER ? &user_pool : &kernel_pool;
  void* pages;
  size_t page_idx;

  if (page_cnt == 0)
    return NULL;

  lock_acquire(&pool->lock);
  page_idx = bitmap_scan_and_flip(pool->used_map, 0, page_cnt, false);
  lock_release(&pool->lock);

  if (page_idx != BITMAP_ERROR)
    pages = pool->base + PGSIZE * page_idx;
  else
    pages = NULL;

  if (pages != NULL) {
      if (flags & PAL_ZERO) {
          memset(pages, 0, PGSIZE * page_cnt);
          for (int i = 0; i < page_cnt; i++) {
              struct frame_entry* frame = malloc(sizeof(struct frame_entry));
              if (frame == NULL) {
                  PANIC("palloc get NULL frame_entry\n");
              }
              frame->page = (void*)((char*)pages + (PGSIZE * i));
              frame->ref_cnt = 1;
              hash_insert(&frame_table, &frame->elem);
          }
      }
  } else {
    if (flags & PAL_ASSERT)
      PANIC("palloc_get: out of pages");
  }

  return pages;
}

/* 获取一个空闲页面并返回其内核虚拟地址。如果设置了 PAL_USER，则从用户池获取该页面；
   否则，从内核池获取。如果在 FLAGS 中设置了 PAL_ZERO，则该页面将被填充为零。
   如果没有可用页面，则返回空指针，除非在 FLAGS 中设置了 PAL_ASSERT，
   在这种情况下，内核将发生 panic。 */
void* palloc_get_page(enum palloc_flags flags) { return palloc_get_multiple(flags, 1); }

/* Frees the PAGE_CNT pages starting at PAGES. */
void palloc_free_multiple(void* pages, size_t page_cnt) {

  struct pool* pool;
  size_t page_idx;

  ASSERT(pg_ofs(pages) == 0);
  if (pages == NULL || page_cnt == 0)
    return;

  if (page_from_pool(&kernel_pool, pages))
    pool = &kernel_pool;
  else if (page_from_pool(&user_pool, pages))
    pool = &user_pool;
  else
    NOT_REACHED();

  page_idx = pg_no(pages) - pg_no(pool->base);

// #ifndef NDEBUG
//   memset(pages, 0xcc, PGSIZE * page_cnt);
// #endif
  // ASSERT(bitmap_all(pool->used_map, page_idx, page_cnt));
  // bitmap_set_multiple(pool->used_map, page_idx, page_cnt, false);
  /* 改成一页一页判断是否需要释放 */
  for (int i = 0; i < page_cnt; i++) {
      ASSERT(bitmap_all(pool->used_map, page_idx+i, 1));
      char* addr = (char*)pages + i*PGSIZE;

      struct frame_entry lookup;
      lookup.page = addr;  // 只需要设置用于比较的字段
      struct hash_elem* e = hash_find(&frame_table, &lookup.elem);

      if (e != NULL) {
          struct frame_entry* f = hash_entry(e, struct frame_entry, elem);
          f->ref_cnt--;
          
          if (f->ref_cnt == 0) {
            #ifndef NDEBUG
              // memset(page_idx + i, 0xcc, PGSIZE);
            #endif
              bitmap_set_multiple(pool->used_map, page_idx + i, 1, false);
              hash_delete(&frame_table, &f->elem);// 从哈希表中移除
              free(f);
          }
    }
  }


}

/* Frees the page at PAGE. */
void palloc_free_page(void* page) { palloc_free_multiple(page, 1); }

/* Initializes pool P as starting at START and ending at END,
   naming it NAME for debugging purposes. */
static void init_pool(struct pool* p, void* base, size_t page_cnt, const char* name) {
  /* We'll put the pool's used_map at its base.
     Calculate the space needed for the bitmap
     and subtract it from the pool's size. */
  size_t bm_pages = DIV_ROUND_UP(bitmap_buf_size(page_cnt), PGSIZE);
  if (bm_pages > page_cnt)
    PANIC("Not enough memory in %s for bitmap.", name);
  page_cnt -= bm_pages;

  printf("%zu pages available in %s.\n", page_cnt, name);

  /* Initialize the pool. */
  lock_init(&p->lock);
  p->used_map = bitmap_create_in_buf(page_cnt, base, bm_pages * PGSIZE);
  p->base = base + bm_pages * PGSIZE;
}

/* Returns true if PAGE was allocated from POOL,
   false otherwise. */
static bool page_from_pool(const struct pool* pool, void* page) {
  size_t page_no = pg_no(page);
  size_t start_page = pg_no(pool->base);
  size_t end_page = start_page + bitmap_size(pool->used_map);

  return page_no >= start_page && page_no < end_page;
}


/* ========== hash ========== */
/* 计算 frame_entry 的哈希值（基于物理页面地址） */
static unsigned frame_hash_func(const struct hash_elem* e, void* aux UNUSED) {
    const struct frame_entry* f = hash_entry(e, struct frame_entry, elem);
    return hash_int((int)f->page);  // 使用页面地址作为哈希键
}

/* 比较两个 frame_entry（基于物理页面地址） */
static bool frame_less_func(const struct hash_elem* a, 
                           const struct hash_elem* b, 
                           void* aux UNUSED) {
    const struct frame_entry* fa = hash_entry(a, struct frame_entry, elem);
    const struct frame_entry* fb = hash_entry(b, struct frame_entry, elem);
    return fa->page < fb->page;
}

struct frame_entry* hash_get_page(uint32_t* page) {
    struct frame_entry lookup;
    lookup.page = page;  // 只需要设置用于比较的字段
    struct hash_elem* e = hash_find(&frame_table, &lookup.elem);

    if (e != NULL) {
        struct frame_entry* f = hash_entry(e, struct frame_entry, elem);
        return f;
    } else {
        return NULL;
    }
}

void increace_frame_ref(uint32_t* kpage) {
    if (kpage == NULL) {
        printf("NULL kpage\n");
        return;
    }
    struct frame_entry* f = hash_get_page(kpage);    
    if (f != NULL)  
      f->ref_cnt++;
}

void decreace_frame_ref(uint32_t* kpage) {
    if (kpage == NULL) {
        printf("NULL kpage\n");
        return;
    }
    struct frame_entry* f = hash_get_page(kpage);  
    if (f != NULL) {
        f->ref_cnt--;
        if (f->ref_cnt == 0) {
            // palloc_free_multiple(kpage,1);
            
            hash_delete(&frame_table, &f->elem);// 从哈希表中移除
            free(f);

            struct pool* pool;
            if (page_from_pool(&kernel_pool, kpage))
                pool = &kernel_pool;
            else if (page_from_pool(&user_pool, kpage))
                pool = &user_pool;

        #ifndef NDEBUG
            memset(kpage, 0xcc, PGSIZE);  // 只在真正释放时清零
        #endif
            size_t page_idx = pg_no(kpage) - pg_no(pool->base);
            ASSERT(bitmap_test(pool->used_map, page_idx));
            bitmap_set(pool->used_map, page_idx, false);
        }
    }

}