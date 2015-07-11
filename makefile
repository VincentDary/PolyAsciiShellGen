################################################################
############ Date: February 3 2015
############ Author: Vincent Dary
############ File: makefile
############ Licence: GPLv3
############ Description: compiles the PolyAsciiShellGen program
################################################################

.PHONY: clean, mrproper
.SUFFIXES:

BIN = PolyAsciiShellGen
CC = gcc
CFLAGS = -W -Wall -g

all: main.o AllocFunctions.o CmdLineTtmt.o AsciiShellEngine.o
	$(CC) $^ -o $(BIN) $(CFLAGS)

main.o: AllocFunctions.h CmdLineTtmt.h AsciiShellEngine.h

%.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS)

clean:
	rm -rf *.o



