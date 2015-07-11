//##############################################################################
//
// Date: May 18 2018
// Author: Vincent Dary
// File: vuln_ascii_filter_sample.c
// Licence: GPLv3
// Description: This program contain a stack buffer overflow vulnerability
//              designed specialy to show when an ASCII shellcode can be useful
//              in buffer overflow exploitation.
// Compile line: gcc vuln_ascii_filter_sample.c -o vuln_ascii_filter_sample
//                   -m32
//                   -z execstack
//                   -fno-stack-protector
//                   -no-pie
//
//##############################################################################

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

#define BOOK_COMMENT_MAX_LEN 512
#define BOOK_REF_MAX_LEN 48

struct book_info {
    char comment[BOOK_COMMENT_MAX_LEN];
    char book_ref[4];  /* programming error */
};

int register_book(){
    struct book_info b_info;
    size_t comment_size = 0;
    size_t i = 0;

    memset(&b_info, 0, sizeof(b_info));

    printf("[0x%x] @b_info.comment\n", &b_info.comment);
    printf("[0x%x] @b_info.book_ref\n", &b_info.book_ref);

    puts("[+] Enter a book reference: ");
    if( fgets(b_info.book_ref, BOOK_REF_MAX_LEN-1, stdin) == NULL )
        return -1;

    puts("[+] Enter a book commentary: ");
    if( fgets(b_info.comment, BOOK_COMMENT_MAX_LEN-1, stdin) == NULL )
        return -1;

    /* ASCII filter 0x20 to 0x7E */
    comment_size = strlen(b_info.comment);
    for( i=0; i < comment_size-1; ++i ){
        if(! (isprint(b_info.comment[i])) ){
            memset(&b_info, 0, sizeof(b_info));
            return -1;
        }
    }

    puts("[+] Book registered.");
    printf("\nreference: %s\ncommentary: %s\n", b_info.book_ref, b_info.comment);
    return 0;
}

int main(int argc, char *argv[]){
    if( register_book() < 0 ){
        puts("[-] Error during book registering.");
        return 1;
    }
    return 0;
}
