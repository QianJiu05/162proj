/* Invokes an exec system call with the exec string straddling a
   page boundary such that the first byte of the string is valid
   but the remainder of the string is in invalid memory. Must
   kill process. */

#include <syscall-nr.h>
#include "tests/userprog/boundary.h"
#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) {
  char* p = get_bad_boundary() - 1;
  *p = 'a';
  exec(p);

  /* 注意：如果即使使用官方解决方案，此测试仍然无法通过，
     可能是因为内存布局发生了变化，p 不再指向正确的页边界。
     要解决此问题，请取消注释下面的行以打印出边界地址。此外，
     在 load_segment 中添加一行 printf 以打印出每个段的地址范围。
     由此，您将能够弄清楚如何修改 get_bad_boundary 以使其再次正常工作。*/

//   msg("boundary address: 0x%x", p);
  fail("should have killed process");
}
