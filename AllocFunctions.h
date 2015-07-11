//################################################################
//############ Date: June 29 2015
//############ Author: Vincent Dary
//############ File: AllocFunctions.h
//############ Licence: GPLv3
//############ Description: memory allocation function.
//################################################################

#ifndef ALLOCFUNCTIONS_H_INCLUDED
#define ALLOCFUNCTIONS_H_INCLUDED

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

void * mem_alloc(const size_t allocSize, size_t sizeType);

#endif
