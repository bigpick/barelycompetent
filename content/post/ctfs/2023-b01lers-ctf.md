---
title: "b01lers CTF 2023"
description: "Writeups for problems solved by gp for the 2023 b01lers CTF competition."
date: 2023-03-19T09:24:19-05:00
url: "/ctfs/2023/b01lers-ctf-writeups"
type:
 - post
categories:
 - capture the flag writeups
tags:
 - ctfs
---

## Intro

> b01lers CTF is the public competitive CTF hosted by the Purdue Capture The
> Flag team.
>
> Registration will open approximately 2 weeks prior to the event. Join our
> discord at discord.gg/tBMqujE and stay posted for further info at
> https://ctf.b01lers.com
>
> Infrastructure sponsored by goo.gle/ctfsponsorship
>
> Happy hacking!

## Solved

| Misc                                | Rev                 | Web               |
| ----------------------------------- | ------------------- | ----              |
| [abhs](abhs)                        | [padlock](#padlock) | [warmup](#warmup) |
| [no-copy-allowed](#no-copy-allowed) |                     |                   |

### Misc

#### abhs

> Just a warmup.
>
> `nc abhs.bctf23-codelab.kctf.cloud 1337`


#### no-copy-allowed

> keep doing this until you get bored.
>
> http://ctf.b01lers.com:5125

### Rev

#### padlock

> Mindblown by ioccc? How can someone write programs like this... Anyway, try open this padlock :)
>
> _files: quine.c_

Attached is `quine.c`:

```c
              #include/*firt*/<stdio.h>
           #define/*ah*/      p/**/putchar
         #define/*??*/         c/*cal*/char
        #define/*to*/           Q(q)int*P,u\
        /*why...*/=0,           M[99999],*C\
        =M,*S=M+293;c           *Q=#q/*am*/\
        ,H[99999],*D=           H;/*i*/int(\
        main)(int*a,c           **b){q;}/**/
/*quine*/Q(int*B=M+549;int/*ahhh*/l=strlen(b[1]);p(47);
p(47);for(;*Q;Q++){if(*Q==124)*C++=10;else/*haaa*/if(*Q
==126)*C++=32;else/*wtf_is_this*/if(*Q==33)*C++=34;else
/*woeira*/if(*Q>34)*C++=*Q;*D++=*Q==32?'\n':*Q;}for(int
u=-0;u<l*4;)p(-b[1][u/4]+S[u++]-S[u++]+(S[u++]^S[u++])?
88:79);p(10);/*weird___*/for(int*d=B;d<M+1280;)p(*d++);
printf("%s)",/*progra*/H+304);return/*UwU*/0**"^O{(u4X"
"z}e(tiIh.p+}Kj<&eb]0@sHecW^[.xroBCW=N3nG+r.]rGEs.UJw^"
"y'tn_Qv(y;Ed')#@q@xI1N:wH<X1aT)NtMvNlcY0;+x[cQ4j9>Qi2"
"#Yq&fR#os=ELTjS^/deJZ;EuY`#IQwKL)w<N<Zh,;W9X=&t0zX&E0"
"e<_3SVaLs(pXk6z-XGHTx8T/?-^`h[K0h}`dD6kX:vEeC,mI5fR9k"
"]{;yfO0Wg/1-Z^=WyUqN5XY1g25K1sJgKzfG.~~~~~~~~~~~~~~#i"
"nclude/*firt*/<stdio.h>|~~~~~~~~~~~#define/*ah*/~~~~~"
"~p/**/putchar|~~~~~~~~~#define/*??*/~~~~~~~~~c/*cal*/"
"char|~~~~~~~~#define/*to*/~~~~~~~~~~~Q(q)int*P,u\|~~~"
"~~~~~/*why...*/=0,~~~~~~~~~~~M[99999],*C\|~~~~~~~~=M,"
"*S=M+293;c~~~~~~~~~~~*Q=#q/*am*/\|~~~~~~~~,H[99999],*"
"D=~~~~~~~~~~~H;/*i*/int(\|~~~~~~~~main)(int*a,c~~~~~~"
"~~~~~**b){q;}/**/|/*quine*/Q(int*B=M+549;int/*ahhh*/l"
"=strlen(b[1]);p(47);|p(47);for(;*Q;Q++){if(*Q==124)*C"
"++=10;else/*haaa*/if(*Q|==126)*C++=32;else/*wtf_is_th"
"is*/if(*Q==33)*C++=34;else|/*woeira*/if(*Q>34)*C++=*Q"
";*D++=*Q==32?'\n':*Q;}for(int|u=-0;u<l*4;)p(-b[1][u/4"
"]+S[u++]-S[u++]+(S[u++]^S[u++])?|88:79);p(10);/*weird"
"___*/for(int*d=B;d<M+1280;)p(*d++);|printf(!%s)!,/*pr"
"ogra*/H+304);return/*UwU*//*quine*/Q(/*random_stuf*/")
```

### Web

#### warmup

> My first flask app, I hope you like it
>
> http://ctf.b01lers.com:5115
