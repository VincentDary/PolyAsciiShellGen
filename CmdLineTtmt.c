//################################################################
//############ Date: June 29 2015
//############ Author: Vincent Dary
//############ File: CmdLineTtmt.c
//############ Licence: GPLv3
//############ Description: processing the command line of the
//############              PolyAsciiShellGen program.
//################################################################

#include "CmdLineTtmt.h"


// The usage of the PolyAsciiShellGen program.
//
void usage(void)
{
        puts("\n usage: PolyAsciiShellGen <esp offset>"\
                                     	" <nop sleed factor N * 4 NOPS>"\
                                     	" <shellcode \"\\xOP\\xOP\"...>\n");
}


// This function desallocates the memory for a SmashStackArgs structure.
//
// parameters:
//              net: a SmashStackArgs struture to desallocate
//
void free_smashstackargs(struct SmashStackArgs *args)
{
	if(args != NULL)
        {
                if(&args->shellcode.mem != NULL)
                {
                        free(args->shellcode.mem);
                        args->shellcode.mem = NULL;
                }

                free(args);
                args = NULL;
        }
}


// Convert a string to a signed integer.
//
// parameters:
//              strValue: a signed integer in text form
//              integer: a signed integer to store the conversion
//
// return: 0 on success or -1 if it is not a valid value.
//
int stoi(const char *strValue, int *integer)
{
        long int ret   = 0;

        if(strValue == NULL  ||  integer == NULL)
                return -1;
        *integer = 0;

        if(strlen(strValue) == 1  &&  *strValue == '0')
                return 0;

        ret =  strtol(strValue, NULL, 0);
        if(ret ==  LONG_MAX  || ret == LONG_MIN  || ret == 0)
                return -1;
        if(ret < -2147483648   ||  ret > 2147483647)
                return -1;

        *integer = ret;
        return 0;

}


// Convert a string to an unsigned integer.
//
// parameters:
//              strValue: an unsigned integer in text form
//              integer: an unsigned integer to store the conversion
//
// return: 0 on success or -1 if it is not a valid value.
//
int stoui(const char *strValue, unsigned int *integer)
{
        unsigned long int ret   = 0;

        if(strValue == NULL  ||  integer == NULL)
                return -1;
        *integer = 0;

        if(strlen(strValue) == 1  &&  *strValue == '0')
                return 0;

        ret =  strtoul(strValue, NULL, 0);
        if(ret ==  ULONG_MAX  ||  ret == 0)
                return -1;
        if(ret > 0xffffffff)
                return -1;

        *integer = ret;
        return 0;
}


// This function checks if the inputShellcode in text form is a valid shellcode.
// The input shellcode must be of the form "\xOP\xOP..."
//
// parameters:
//              inputShellcode: the shellcode to check
//
// return: if is a valid shellcode the function returns 0.
//         If the shellcode if malformed the function returns -1.
//
int is_valid_shellcode(const char *shellcode)
{
        size_t i        = 0;
        size_t j        = 0;
        size_t len      = 0;

        if(shellcode == NULL)
                return -1;

        len = strlen(shellcode);

        if(len % 2 != 0)
                return -1;

        for(i = 0; i < len; )
        {
                if(shellcode[i++] != '\\')
                        return -1;

                if(shellcode[i++] != 'x')
                        return -1;

                for(j = 0; j < 2; ++j)
                {

                        if(shellcode[i] < 0x30  ||  shellcode[i] > 0x39)
                                if(shellcode[i] < 0x61  ||  shellcode[i] > 0x66)
                                        if(shellcode[i] < 0x41 || shellcode[i] > 0x46)
                                                return -1;
                        ++i;
                }
        }

        return 0;
}


// This function performs the conversion of a shellcode in text form to a shellcode in numerical
// representation.
//
// parameters:
//              shellcode: a shellcode in text form ("\xOP\xOP")
//              numeric: a memory block to store the numerical shellcode
//              memSize: the size of memory block allocated
//
// return: return: 0 on success or -1 if it fails
//
int string_shellcode_numerical(const char *shellcode, unsigned char **numeric, size_t *size)
{
	size_t allocSize	= 0;
	size_t nbOpcode	 	= 0;
	size_t rest	 	= 0;
	size_t i	 	= 0;
	size_t strIndex		= 0;
	char tmp[3]		= {0};
	char opcode		= 0;
	unsigned char *ptr	= NULL;

	if(numeric == NULL  ||  size == NULL  || is_valid_shellcode(shellcode) < 0)
		return -1;

	nbOpcode = strlen(shellcode) /4;
	rest = nbOpcode % 4;
	if(rest == 0)
		allocSize = nbOpcode;
	else
		allocSize = nbOpcode + (4 - rest);

	*numeric = mem_alloc(allocSize, sizeof(unsigned char));
	if(*numeric == NULL)
		return -1;
	*size = allocSize;

	tmp[2] = 0;
	strIndex = 2;
	ptr = *numeric;
	for(i = 0; i < nbOpcode; ++i)
	{
		tmp[0] =  shellcode[strIndex++];
                tmp[1] =  shellcode[strIndex];
		strIndex += 3;
		opcode = strtoul(tmp, 0, 16);
		*(ptr+i) = opcode;
	}

	if(rest != 0)
		for(i = 0; i < (4 - rest); ++i)
			*(ptr+nbOpcode+i) = 0x90;

	return 0;
}


// This function sets the PolyAsciiShellGen arguments from the command line.
//
// parameters:
//              argv: a tab of strings that contains the arguments of the command line
//              args: a SmashStackArgs structure to store the results of the arguments of the command line
//
// return: 0 on success or -1 if the arguments are not good.
//
int set_args_polyengine(const char *argv[], struct SmashStackArgs *injection)
{
	if(argv == NULL  || injection == NULL)
		return -1;

	if(stoi(argv[1],  &injection->espOffset) < 0)
	{
		printf("[-] The esp offset is not valid: %s\n", argv[1]);
		return -1;
	}
	if(stoui(argv[2], &injection->nopSleedToShell) < 0)
        {
		printf("[-] The nop sleed value is not valid: %s\n", argv[2]);
		return -1;
	}
	if(is_valid_shellcode(argv[3]) < 0)
        {
		printf("[-] The shellcode's opcodes are malformed:\n    %s\n", argv[3]);
                return -1;
	}
	if(string_shellcode_numerical(argv[3], &(injection->shellcode.mem), &(injection->shellcode.size)) < 0)
		return -1;

	return 0;
}


// This function performs the treatment of the command line's arguments.
//
//              argc: the number of arguments of the commmand line
//              argv: a tab of strings that contains the arguments of the command line
//              args: a SmashStackArgs structure to store the results of the arguments of the command line
//
// return: 0 on success or -1 if there is not all the arguments in the command line.
//
int cmd_ttmt(const int argc, const char *argv[], struct SmashStackArgs **injection)
{
	if(argv == NULL  ||  injection == NULL)
		return -1;

	if(argc != 4)
		usage();
	else
	{
		*injection = mem_alloc(1, sizeof(struct SmashStackArgs));
	      	if(*injection == NULL)
	           	return -1;

		if(set_args_polyengine(argv, *injection) < 0)
			return -1;
	}

	return 0;
}

