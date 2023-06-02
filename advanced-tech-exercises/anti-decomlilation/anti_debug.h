#ifndef _ANTI_DEBUG_H_
#define _ANTI_DEBUG_H_

typedef int bool;
#define true 1
#define false 0

void dbg_checker();
int check_ptrace();
int dbg_file_descriptor();
int dbg_cmdline();
int dbg_getppid_name();
int various_ldpreload();

#endif