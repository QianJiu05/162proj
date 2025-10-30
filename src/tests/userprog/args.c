/* Prints the command-line arguments.
   This program is used for all of the args-* tests.  Grading is
   done differently for each of the args-* tests based on the
   output. */

#include "tests/lib.h"
#include <stdio.h>
int main(int argc, char* argv[]) {
  int i;

  test_name = "args";
  printf("testname = %s\n",test_name);

  msg("begin");
  printf("begin\n");
  msg("argc = %d", argc);
  for (i = 0; i <= argc; i++)
    if (argv[i] != NULL)
      msg("argv[%d] = '%s'", i, argv[i]);
    else
      msg("argv[%d] = null", i);
  msg("end");

  return 0;
}
