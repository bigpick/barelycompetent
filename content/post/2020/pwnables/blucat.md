---
title: "Blukat: The stupid way"
excerpt: "pwnable.kr challenge: blukat"
date: 2020-03-25T09:24:19-05:00
categories:
 - pwn practice
url: "/pwnable.kr/blukat"
tags:
 - pwnable.kr
---

# pwnable.kr: blukat

> Sometimes, pwnable is strange...
> hint: if this challenge is hard, you are a skilled player.
>
> `ssh blukat@pwnable.kr -p2222 (pw: guest)`

## Given
Location of which the vulnerable program is currently running:
* `ssh blukat@pwnable.kr -p2222`

## First, lets get on the box

```bash
ls
blukat	blukat.c  password
```


## Run it

```bash
./blukat
guess the password!
AAAAAAAAAAAAAAAAAAA
wrong guess!
```

## Examine (given) source code

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
char flag[100];
char password[100];
char* key = "3\rG[S/%\x1c\x1d#0?\rIS\x0f\x1c\x1d\x18;,4\x1b\x00\x1bp;5\x0b\x1b\x08\x45+";
void calc_flag(char* s){
	int i;
	for(i=0; i<strlen(s); i++){
		flag[i] = s[i] ^ key[i];
	}
	printf("%s\n", flag);
}
int main(){
	FILE* fp = fopen("/home/blukat/password", "r");
	fgets(password, 100, fp);
	char buf[100];
	printf("guess the password!\n");
	fgets(buf, 128, stdin);
	if(!strcmp(password, buf)){
		printf("congrats! here is your flag: ");
		calc_flag(password);
	}
	else{
		printf("wrong guess!\n");
		exit(0);
	}
	return 0;
}
```

So it's reading in the file, then comparing our input with the password, and if so give's us the flag.

Let's see if we can examine what that password is in Peda:

```python
break *main
r
context code 60
...
   0x400857 <main+93>:	call   0x400640 <fgets@plt>
   0x40085c <main+98>:	lea    rax,[rbp-0x70]
   0x400860 <main+102>:	mov    rsi,rax
   0x400863 <main+105>:	mov    edi,0x6010a0
   0x400868 <main+110>:	call   0x400650 <strcmp@plt>
   0x40086d <main+115>:	test   eax,eax
   0x40086f <main+117>:	jne    0x4008a0 <main+166>
...
break *0x400868
c
```
Then we can examine the values, `0x6010a0` is the password;

```python
x/5x 0x6010a0
0x6010a0 <password>:	0x736170203a746163	0x50203a64726f7773
0x6010b0 <password+16>:	0x6f697373696d7265	0x6465696e6564206e
0x6010c0 <password+32>:	0x000000000000000a
```

Can convert that to a string using python:

```python
>>> import binascii
>>> binascii.unhexlify('736170203a746163')
b'sap :tac'
>>> binascii.unhexlify('50203a64726f7773')
b'P :drows'
>>> binascii.unhexlify('6f697373696d7265')
b'oissimre'
>>> binascii.unhexlify('6465696e6564206e')
b'deined n'
```

Huh? So that looks like `cat: password: Permission denied` is the password. And indeed, passing that to the program gets us our flag.

```bash
blukat@pwnable:~$ ./blukat
guess the password!
cat: password: Permission denied
congrats! here is your flag: _______________________
```

## Note to self afterwards...

**Use `ls -alrt` and `id` first!**. We would have noticed we already had permissions to just `cat` the password file as is:

```bash
id
uid=1104(blukat) gid=1104(blukat) groups=1104(blukat),1105(blukat_pwn)

ls -alrt
-rw-r-----   1 root blukat_pwn   33 Jan  6  2017 password
```

So we can just cat the file straight from the command line! :facepalm:
