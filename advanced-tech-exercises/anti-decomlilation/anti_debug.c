#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>

typedef int bool;
#define true 1
#define false 0

#define check_strings(str_buff) (strstr(str_buff, "gdb") || strstr(str_buff, "ltrace") || strstr(str_buff, "strace") || (strstr(str_buff, "radare2")) || (strstr(str_buff, "ida")))

void dbg_checker();
int check_ptrace();
int dbg_file_descriptor();
int dbg_cmdline();
int dbg_getppid_name();
int various_ldpreload();

void dbg_checker()
{
  /* prevent core dump */
  prctl(PR_SET_DUMPABLE, 0);

  if (check_ptrace() == 1)
  {
    exit(0);
  }

  if (dbg_file_descriptor() == 1)
  {
    exit(0);
  }

  if (dbg_cmdline() == 1)
  {
    exit(0);
  }

  if (dbg_getppid_name() == 1)
  {
    exit(0);
  }

  if (various_ldpreload() == 1)
  {
    exit(0);
  }
}

/* Check if ptrace is already attached */
int check_ptrace()
{
  return ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0;
}

/* 2 file descriptors when programs open with GDB. Both pointing to the program being debugged.*/
int dbg_file_descriptor()
{
    FILE* fd = fopen("/", "r");
    int nb_fd = fileno(fd);
    fclose(fd);

    return (nb_fd > 3);
}

/* Detect GDB by the mean of /proc/$PID/cmdline, which should no be "gdb" */
int dbg_cmdline()
{
    char buff [24], tmp [16];
    FILE* f;

    snprintf(buff, 24, "/proc/%d/cmdline", getppid());
    f = fopen(buff, "r");
    fgets(tmp, 16, f);
    fclose(f);

    return check_strings(tmp);
}

/* Check the parent's name */
int dbg_getppid_name()
{
    char buff1[24], buff2[16];
    FILE* f;

    snprintf(buff1, 24, "/proc/%d/status", getppid());
    f = fopen(buff1, "r");
    fgets(buff2, 16, f);
    fclose(f);

    return check_strings(buff2);
}

/* Try to detect the LD_PRELOAD trick by looking into environnement variables of the program. */
int various_ldpreload()
{
    return (getenv("LD_PRELOAD") != NULL);
}