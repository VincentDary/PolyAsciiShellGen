//##############################################################################
//
// Date: October 01 2018
// Author: Vincent Dary
// File: exec_wrapper.c
// Licence: GPLv3
// Description: Restrictive binary loader with an empty environnement. Fix the
//              lack of gdb option to provide a total empty environnement to
//              the launched binary.
//
// Compile line: gcc -m32 exec_wrapper.c -o exec_wrapper
//
//##############################################################################

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

int main(int argc, char *argv[])
{
    int e;

    char exec_bin_name[] = "./vuln_ascii_filter_sample";
    char *exec_argv[] = { exec_bin_name, NULL };
    char *exec_envp[] = { NULL };

    printf("\n\n[demo exec wrapper] Executing %s\n\n", exec_bin_name);

    e = execve(exec_bin_name, exec_argv, exec_envp);

    if (e == -1)
        fprintf(stderr, "[demo exec wrapper] error %s\n", strerror(errno));

    return 0;
}
