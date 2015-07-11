//################################################################
//############ Date: June 29 2015
//############ Author: Vincent Dary
//############ File: AllocFunctions.c
//############ Licence: GPLv3
//############ Description: memory allocation function.
//################################################################

#include "AllocFunctions.h"

// Performs a memory allocation.
//
// parameters:
//              alloSize: the memory allocation size
//              sizeType: the size type of the memory allocation
//
// return: a pointer to the new memory block or NULL if it fails.
//
void * mem_alloc(const size_t allocSize, size_t sizeType)
{
	void *ptr = NULL;

        if(allocSize == 0 || sizeType == 0)
                return NULL;

        ptr = malloc(allocSize * sizeType);

        if(ptr == NULL)
        {
                printf("[-] %s : %s\n", __FUNCTION__, strerror(errno));
                return NULL;
        }

        return ptr;
}

