//################################################################
//############ Date: June 29 2015
//############ Author: Vincent Dary
//############ File: CmdLineTtmt.h
//############ Licence: GPLv3
//############ Description: processing the command line of the
//############              PolyAsciiShellGen program.
//################################################################

#ifndef CMDLINETTMT_H_INCLUDED
#define CMDLINETTMT_H_INCLUDED

#include <limits.h>
#include "AllocFunctions.h"


struct Shellcode
{
	unsigned char *mem;
	size_t size;
};

struct SmashStackArgs
{
        int 			espOffset;
        unsigned int 		nopSleedToShell;
	struct 	Shellcode	shellcode;
};


void    usage(void);
void	free_smashstackargs(struct SmashStackArgs *args);
int 	stoui(const char *strValue, unsigned int *integer);
int 	is_valid_shellcode(const char *shellcode);
int	string_shellcode_numerical(const char *shellcode, unsigned char **numeric, size_t *size);
int	set_args_polyengine(const char *argv[], struct SmashStackArgs *injection);
int 	cmd_ttmt(const int argc, const char *argv[], struct SmashStackArgs **injection);

#endif

