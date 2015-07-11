//################################################################
//############ Date: June 29 2015
//############ Author: Vincent Dary
//############ File: main.c
//############ Licence: GPLv3
//############ Description: PolyAsciiShellGen entry point.
//################################################################

#include "AsciiShellEngine.h"

int main(int argc, char *argv[])
{
	if(poly_ascii_shellcode_entry(argc, (const char **)argv) < 0)
		return 1;

	return 0;
}
