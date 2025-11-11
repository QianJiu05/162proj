#include "userprog/pagedir.h"
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "threads/init.h"
#include "threads/pte.h"
#include "threads/palloc.h"

static void invalidate_pagedir(uint32_t*);

/* Creates a new page directory that has mappings for kernel
   virtual addresses, but none for user virtual addresses.
   Returns the new page directory, or a null pointer if memory
   allocation fails. */
uint32_t* pagedir_create(void) {
  uint32_t* pd = palloc_get_page(0);
  if (pd != NULL)
    memcpy(pd, init_page_dir, PGSIZE);
  return pd;
}

/* Destroys page directory PD, freeing all the pages it
   references. */
void pagedir_destroy(uint32_t* pd) {
  uint32_t* pde;

  if (pd == NULL)
    return;

  ASSERT(pd != init_page_dir);
  for (pde = pd; pde < pd + pd_no(PHYS_BASE); pde++)
    if (*pde & PTE_P) {
      uint32_t* pt = pde_get_pt(*pde);
      uint32_t* pte;

      for (pte = pt; pte < pt + PGSIZE / sizeof *pte; pte++)
        if (*pte & PTE_P)
          palloc_free_page(pte_get_page(*pte));
      palloc_free_page(pt);
    }
  palloc_free_page(pd);
}

/* Returns the address of the page table entry for virtual
   address VADDR in page directory PD.
   If PD does not have a page table for VADDR, behavior depends
   on CREATE.  If CREATE is true, then a new page table is
   created and a pointer into it is returned.  Otherwise, a null
   pointer is returned.
   返回页面目录 PD 中虚拟地址 VADDR 的页表项地址。
   如果 PD 没有 VADDR 的页表，则行为取决于 CREATE 语句。
   如果 CREATE 语句为真，则会创建一个新的页表，
   并返回指向该页表的指针。否则，返回一个空指针。
*/
static uint32_t* lookup_page(uint32_t* pd, const void* vaddr, bool create) {
  uint32_t *pt, *pde;

  ASSERT(pd != NULL);

  /* Shouldn't create new kernel virtual mappings. */
  ASSERT(!create || is_user_vaddr(vaddr));

  /* Check for a page table for VADDR.
     If one is missing, create one if requested. */
  pde = pd + pd_no(vaddr);
  if (*pde == 0) {
    if (create) {
      pt = palloc_get_page(PAL_ZERO);
      if (pt == NULL)
        return NULL;

      *pde = pde_create(pt);
    } else
      return NULL;
  }

  /* Return the page table entry. */
  pt = pde_get_pt(*pde);
  return &pt[pt_no(vaddr)];
}

/* Adds a mapping in page directory PD from user virtual page
   UPAGE to the physical frame identified by kernel virtual
   address KPAGE.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   If WRITABLE is true, the new page is read/write;
   otherwise it is read-only.
   Returns true if successful, false if memory allocation
   failed. 
   在页面目录 PD 中添加一个映射，
   将用户虚拟页面 UPAGE 映射到内核虚拟地址 KPAGE 所标识的物理帧。
   UPAGE 必须尚未被映射。KPAGE 应该是从用户池中获取的页面，
   可通过 palloc_get_page() 获取。
   如果 WRITABLE 为真，则新页面可读写；否则，它是只读的。
   成功则返回 true，失败则返回 false。
*/
bool pagedir_set_page(uint32_t* pd, void* upage, void* kpage, bool writable) {
  uint32_t* pte;

  ASSERT(pg_ofs(upage) == 0);
  ASSERT(pg_ofs(kpage) == 0);
  ASSERT(is_user_vaddr(upage));
  ASSERT(vtop(kpage) >> PTSHIFT < init_ram_pages);
  ASSERT(pd != init_page_dir);

  pte = lookup_page(pd, upage, true);

  if (pte != NULL) {
    ASSERT((*pte & PTE_P) == 0);
    *pte = pte_create_user(kpage, writable);
    return true;
  } else
    return false;
}

/* Looks up the physical address that corresponds to user virtual
   address UADDR in PD.  Returns the kernel virtual address
   corresponding to that physical address, or a null pointer if
   UADDR is unmapped. 
   查找与 PD 中的用户虚拟地址 UADDR 对应的物理地址。
   返回与该物理地址对应的内核虚拟地址，如果 UADDR 未映射，则返回空指针。*/
void* pagedir_get_page(uint32_t* pd, const void* uaddr) {
  uint32_t* pte;

  // ASSERT(is_user_vaddr(uaddr));
  if(!is_user_vaddr(uaddr)){
      return NULL;
  }

  pte = lookup_page(pd, uaddr, false);
  if (pte != NULL && (*pte & PTE_P) != 0)
    return pte_get_page(*pte) + pg_ofs(uaddr);
  else
    return NULL;
}

/* Marks user virtual page UPAGE "not present" in page
   directory PD.  Later accesses to the page will fault.  Other
   bits in the page table entry are preserved.
   UPAGE need not be mapped. */
void pagedir_clear_page(uint32_t* pd, void* upage) {
  uint32_t* pte;

  ASSERT(pg_ofs(upage) == 0);
  ASSERT(is_user_vaddr(upage));

  pte = lookup_page(pd, upage, false);
  if (pte != NULL && (*pte & PTE_P) != 0) {
    *pte &= ~PTE_P;
    invalidate_pagedir(pd);
  }
}

/* Returns true if the PTE for virtual page VPAGE in PD is dirty,
   that is, if the page has been modified since the PTE was
   installed.
   Returns false if PD contains no PTE for VPAGE. */
bool pagedir_is_dirty(uint32_t* pd, const void* vpage) {
  uint32_t* pte = lookup_page(pd, vpage, false);
  return pte != NULL && (*pte & PTE_D) != 0;
}

/* Set the dirty bit to DIRTY in the PTE for virtual page VPAGE
   in PD. */
void pagedir_set_dirty(uint32_t* pd, const void* vpage, bool dirty) {
  uint32_t* pte = lookup_page(pd, vpage, false);
  if (pte != NULL) {
    if (dirty)
      *pte |= PTE_D;
    else {
      *pte &= ~(uint32_t)PTE_D;
      invalidate_pagedir(pd);
    }
  }
}

/* Returns true if the PTE for virtual page VPAGE in PD has been
   accessed recently, that is, between the time the PTE was
   installed and the last time it was cleared.  Returns false if
   PD contains no PTE for VPAGE. */
bool pagedir_is_accessed(uint32_t* pd, const void* vpage) {
  uint32_t* pte = lookup_page(pd, vpage, false);
  return pte != NULL && (*pte & PTE_A) != 0;
}

/* Sets the accessed bit to ACCESSED in the PTE for virtual page
   VPAGE in PD. */
void pagedir_set_accessed(uint32_t* pd, const void* vpage, bool accessed) {
  uint32_t* pte = lookup_page(pd, vpage, false);
  if (pte != NULL) {
    if (accessed)
      *pte |= PTE_A;
    else {
      *pte &= ~(uint32_t)PTE_A;
      invalidate_pagedir(pd);
    }
  }
}

/* Loads page directory PD into the CPU's page directory base
   register. */
void pagedir_activate(uint32_t* pd) {
  if (pd == NULL)
    pd = init_page_dir;

  /* Store the physical address of the page directory into CR3
     aka PDBR (page directory base register).  This activates our
     new page tables immediately.  See [IA32-v2a] "MOV--Move
     to/from Control Registers" and [IA32-v3a] 3.7.5 "Base
     Address of the Page Directory". */
  asm volatile("movl %0, %%cr3" : : "r"(vtop(pd)) : "memory");
}

/* Returns the currently active page directory. */
uint32_t* active_pd(void) {
  /* Copy CR3, the page directory base register (PDBR), into
     `pd'.
     See [IA32-v2a] "MOV--Move to/from Control Registers" and
     [IA32-v3a] 3.7.5 "Base Address of the Page Directory". */
  uintptr_t pd;
  asm volatile("movl %%cr3, %0" : "=r"(pd));
  return ptov(pd);
}

/* Seom page table changes can cause the CPU's translation
   lookaside buffer (TLB) to become out-of-sync with the page
   table.  When this happens, we have to "invalidate" the TLB by
   re-activating it.

   This function invalidates the TLB if PD is the active page
   directory.  (If PD is not active then its entries are not in
   the TLB, so there is no need to invalidate anything.) */
static void invalidate_pagedir(uint32_t* pd) {
  if (active_pd() == pd) {
    /* Re-activating PD clears the TLB.  See [IA32-v3a] 3.12
         "Translation Lookaside Buffers (TLBs)". */
    pagedir_activate(pd);
  }
}
