//################################################################
//############ Date: June 29 2015
//############ Author: Vincent Dary
//############ File: AsciiShellEngine.h
//############ Licence: GPLv3
//############ Description: Ascii Shellcode Engine based based on
//############              Riley "caezar" Eller technique.
//############              Bypassing MSB Data Filters for Buffer
//############              Overflow Exploits on Intel Platforms.
//################################################################

#ifndef ASCIISHELLENGINE_H_INCLUDED
#define ASCIISHELLENGINE_H_INCLUDED

#define _GNU_SOURCE

#include <time.h>
#include "CmdLineTtmt.h"

// Basic ascii set
#define CHR 		"%_01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-"
#define CHR_SIZE 	66

// NOP opcode
#define NOP		0x90

// x86 ascii opcodes
#define AND_EAX_32      '%'
#define SUB_EAX_32      '-'
#define PUSH_EAX        'P'
#define POP_EAX         'X'
#define PUSH_ESP        'T'
#define POP_ESP         '\\'

// Ascii shellcode template size
#define ESP_INIT_SIZE                   19
/*
        push esp        T
        pop eax         X
        sub, eax       -xxxx
        sub, eax       -xxxx
        sub, eax       -xxxx
        push eax        \
        pop eax         X
*/
#define EAX_ZERO_SIZE                   10
/*
        and eax, xxxx   %xxxx
        and eax, xxxx   %xxxx
*/
#define SUB_SHELLCODE_TEMPLATE_SIZE     21
/*
        sub eax, xxxx   -xxxx
        sub eax, xxxx   -xxxx
        sub eax, xxxx   -xxxx
	sub eax, xxxx   -xxxx
        push eax        P
*/
#define SUB_NOP_TEMPLATE_SIZE           1
/*
        push eax        P
*/

// sub encoder type
typedef unsigned char EncodedOpcode[4][4];
typedef unsigned char chunk[4];


int	ascii_shellcode_alloc(const size_t shellcodeSize, const unsigned int nopSleedLoadShell,
			      unsigned char **buffer, size_t *size);
int	sub_encoder(const chunk start, const chunk end, EncodedOpcode opCodeAscii);
int	and_eax_zero_encoder(chunk first, chunk second);
int	build_esp_init(unsigned char *buffer, size_t size, int espOffset);
int	build_eax_zero(unsigned char *buffer, size_t size);
int	build_loader_to_shellcode(const unsigned int nopSleedToShell, const chunk eax,
                              unsigned char *buffer, size_t size);
int	build_shellcode_packer(const struct Shellcode *shellcode, const unsigned int nopSleedToShell,
                           unsigned char *buffer, size_t size);
int 	poly_ascii_shellcode_engine(const struct SmashStackArgs *injection, struct Shellcode *asciiShellcode);
int	poly_ascii_shellcode_entry(const int argc, const char *argv[]);

#endif
