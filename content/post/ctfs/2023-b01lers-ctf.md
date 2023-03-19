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
| [abhs](#abhs)                       | [padlock](#padlock) | [warmup](#warmup) |
| [no-copy-allowed](#no-copy-allowed) |                     |                   |

### Misc

#### abhs

> Just a warmup.
>
> `nc abhs.bctf23-codelab.kctf.cloud 1337`

Accessing the box:

```bash
== proof-of-work: disabled ==
== A Bonkers Homemade Shell ==
$ ls
chal.py
flag.txt
wrapper.sh

$ whoami
sh: 1: ahimow: not found

$ pwd
sh: 1: dpw: not found

$ ls -alrt
total 20
-rw-r--r-- 1 nobody nogroup   93 Mar 15 00:18 flag.txt
-rw-r--r-- 1 nobody nogroup  349 Mar 15 00:18 chal.py
-rw-r--r-- 1 nobody nogroup   43 Mar 17 19:39 wrapper.sh
drwxr-xr-x 3 nobody nogroup 4096 Mar 17 19:40 ..
drwxr-xr-x 2 nobody nogroup 4096 Mar 17 19:40 .

$ cat flag.txt
sh: 1: act: not found

$ act
sh: 1: act: not found

$ tac
sh: 1: act: not found
```

It seemed that the box was reversing certain letters in commands for
whatever reason. After playing around on the box for a while, my team
member realized that it was based on alphabetical order. Things like
`ls` and `dd` worked because they were in alphabetical order already.

But doing something like `dd -if` is no longer in order, so the command
gets mangled:

```bash
$ dd -h
dd: invalid option -- 'h'
Try 'dd --help' for more information.

$ dd if=flag.txt
dd: unrecognized operand ‘.=affgilttx’
Try 'dd --help' for more information.
```

After more messing, I found we could use `"*"t` to be able to expand
into `flag.txt`. So all we needed now was a command that could
read a file, and was in alphabetical order.

After 5 seconds my teammate suggested `pr` (which I, a zillenial had
never heard of nor used). Sure enough:

```
$ pr "*"t


2023-03-15 00:18                     flag.txt                     Page 1


#bctf{gr34t_I_gu3ss_you_g0t_that_5orted_out:P}
#
#comments so that you cannot just exec this
...
```

We got the flag. Flag is `bctf{gr34t_I_gu3ss_you_g0t_that_5orted_out:P}`.

#### no-copy-allowed

> keep doing this until you get bored.
>
> http://ctf.b01lers.com:5125

Accessing the page, we get a site that displays some text that needs
to be entered:

{{< image src="/img/CTFs/2023/b01lers/no_copy_home.png" alt="no_copy_home.png" position="center" style="border-radius: 8px;" >}}

In HTML:

```html
<html>
	<head>
        <style>
            @font-face {font-family:b;src:url("index.ttf")}
            p, input { font-size:3vw; }
            span { font-family:b;font-size:2vw; }
            input { border: solid 0.4vw;width:60vw; }
        </style>
	</head>
	<body>
		<table width="100%" height="100%"><tbody><tr><td><center>
            <p>Enter "<span>EIEjtvPAY0fxF4sviaIR90pgg9ob6gFGdBEUihkc</span>" to continue</p><input>
		</center></td></tr></tbody></table>
        <script>
            var input = document.querySelector("input");
            input.addEventListener("keypress", function(e) {
                if (e.keyCode == 13) {
                    window.location.href = input.value + ".html";
                }
            });
        </script>
	</body>
</html>
```

Copy-pasting the EIE... value into the input box and then pressing enter
brings us to a page at http://ctf.b01lers.com:5125/EIEjtvPAY0fxF4sviaIR90pgg9ob6gFGdBEUihkc.html

This makes sense, since the block of code above that has the key code
check is basically saying when you press the enter key (which is `13`),
bring the user to the route that belongs to the value in the input box,
plus `.html`.

After a copy pages though, I realized there was going to be way too
many to do manually, so I threw together something quick to automate
the process:

```bash
stub=EIEjtvPAY0fxF4sviaIR90pgg9ob6gFGdBEUihkc
while true; do
    stub=$(curl "http://ctf.b01lers.com:5125/${stub}.html" | grep Enter | sed 's/.*<span>//g' | sed 's/<\/span.*//g')
    echo "Fetching stub: $stub"
done
```

... which broke after a couple seconds of running:

```text
...
Fetching stub: x70OK5gxhlPEbhmRRmqhimTOSkTz3oAJUTo2VoC8
Fetching stub: vBBEO.CpefN.TBsgS.HfjLG.wcZee.qZrhY.TDFdp.mBbei.IbHlG.tmXTZ.XqBtD.LYzBt.upRSj.EOzlj.izClL.oRdKf.CpefN.XceXS.mBbei.XqBtD.qPcfO.IbHlG.qZrhY.TDFdp.DMmXT.adNyQ.JkxgL.hhGEG.hhGEG.kcXxq.tmXTZ.yWzOK.EtLOl.adNyQ.NliRt.hMtRY.jNjpP.rAufC.EOzlj.yRfgC.
```

Looking at the page at , can see that the text we need to copy is no
longer plain english chars?

```html
		<table width="100%" height="100%"><tbody><tr><td><center>
            <p>Enter "<span>vBBEO.CpefN.TBsgS.HfjLG.wcZee.qZrhY.TDFdp.mBbei.IbHlG.tmXTZ.XqBtD.LYzBt.upRSj.EOzlj.izClL.oRdKf.CpefN.XceXS.mBbei.XqBtD.qPcfO.IbHlG.qZrhY.TDFdp.DMmXT.adNyQ.JkxgL.hhGEG.hhGEG.kcXxq.tmXTZ.yWzOK.EtLOl.adNyQ.NliRt.hMtRY.jNjpP.rAufC.EOzlj.yRfgC.</span>" to continue</p><input>
		</center></td></tr></tbody></table>
```

The browser seems to indicate that it's not english, either. But translating
to the suggested (Hungarian) also doesn't yield a value that when
copy-pasted brings us to the next page.

After a bit of looking, I noticed that the page source also included a
custom font for each page, which seemed strange:

```html
        <style>
            @font-face {font-family:b;src:url("x70OK5gxhlPEbhmRRmqhimTOSkTz3oAJUTo2VoC8.ttf")}
            p, input { font-size:3vw; }
            span { font-family:b;font-size:2vw; }
            input { border: solid 0.4vw;width:60vw; }
        </style>
```

Fetching that font file, and then opening/installing locally, it identifies
as "ZXX Sans", which, after some searching, has interesting history:

> ZXX is a disruptive typeface designed to be undetectable by text scanning software. It takes its name from the Library of Congress’ listing of three-letter codes denoting which language a book is written in, and code “ZXX” means “No linguistic content; Not applicable”. ZXX comes in 6 styles and was researched over the course of one year

After a bit more researching on fonts, I came across the concept of a
ligature substitution lookup table. Basically, a font has a concept of
being able to take a set of chars after a given one, and convert the
result to a specified glyph/ligature. It turns out that the format this
is done with seemed identical to the text on the page: 5 letters followed
by a period.

After more searching, I decided on using https://github.com/fonttools/fonttools
to be able to load the font file, search the glyph table, and return
the resulting character.

```python
#!/usr/bin/env python3

# type: ignore

import requests
from fontTools.ttLib import TTFont
font = TTFont("./x70OK5gxhlPEbhmRRmqhimTOSkTz3oAJUTo2VoC8.ttf")

text_to_num = {
        "one": "1",
        "two": "2",
        "three": "3",
        "four": "4",
        "five": "5",
        "six": "6",
        "seven": "7",
        "eight": "8",
        "nine": "9",
        "zero": "0",
        "underscore": "_",
        "braceleft": "{",
        "braceright": "}"
}

def get_glyph(font, encoding):
    lookup = font["GSUB"].table.LookupList.Lookup[0]
    for char, glyphs in lookup.SubTable[0].ligatures.items():
        for glyph in glyphs:
            comp = char + "".join(glyph.__dict__["Component"]).replace("period", ".")
            if comp == encoding:
                g = glyph.__dict__["LigGlyph"]
                return text_to_num.get(g, g)


snippet = "x70OK5gxhlPEbhmRRmqhimTOSkTz3oAJUTo2VoC8"
# snippet = "wDcIyytPUCxMxQB2YGrlQPDuASUp3ueyjeOnDswA" this is the flag page
while 1<2:
    to_fetch = f"http://ctf.b01lers.com:5125/{snippet}"
    print(f"Fetching: {to_fetch}")

    font_file = f"fonts/{snippet}.ttf"
    with open(font_file, "wb") as outfile:
        outfile.write(requests.get(to_fetch+".ttf").content)

    font = TTFont(font_file)
    resp = requests.get(to_fetch+".html")
    print(resp.text)

    if snippet != "wDcIyytPUCxMxQB2YGrlQPDuASUp3ueyjeOnDswA": # known block added after full successful run
        challenge = [line for line in resp.text.split("\n") if "Enter " in line][0].split()[1][7:-8]
        print("Challenge: ", challenge)
        challenge = [entry for entry in challenge.split(".") if entry]

        next_page = ""
        for grouping in challenge:
            next_page += get_glyph(font, grouping+".")
        snippet = next_page
    else:
        break

challenge = [line for line in resp.text.split("\n") if "<p>" in line][0].split()[0][3:-4]
print("Challenge: ", challenge)
challenge = [entry for entry in challenge.split(".") if entry]

next_page = ""
for grouping in challenge:
    next_page += get_glyph(font, grouping+".")
print(f"Flag: {next_page}")
```

Running the above, we succesfully now can parse the ligature encoded
pages. After running for an absurd number of iterations for no reason,
we get to the page with the flag.

Flag is `bctf{l1gatur3_4bus3_15_fun_X0UOBDvfRkKa99fEVloY0iYuaxzS9hj4rIFXlA3B}`.

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

Compile the program:

```bash
gcc -o quine quine.c
```

Run it. Simple brute force, application takes input, and will tell you `O` or
`X` if the char of your input is correct, in order.

Can just try every possible printable char starting from known flag prefix
until we get `}`:

```python
#!/usr/bin/env python

from string import printable

from subprocess import run, PIPE

known_so_far = 'bctf{'

while 1<2:
    for char in printable:
        results = run("./quine "+known_so_far+char, shell=True, stdout=PIPE, stderr=PIPE)
        if results.stdout:
            score = results.stdout.decode().split("\n")[0][2:]
            if len(score)-len(known_so_far) == 1 and score[-1] == "O":
                known_so_far+=char
                print(known_so_far)
```

Flag is `bctf{qu1n3_1s_4ll_ab0ut_r3p371t10n_4nD_m4n1pul4710n_OwO_OuO_UwU}`.

### Web

#### warmup

> My first flask app, I hope you like it
>
> http://ctf.b01lers.com:5115

Visiting page:

```html

<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>My first flask app</title>
</head>
<body>
    <h1>Hello World!</h1>
</body>
<script>
    console.log("")
</script>
<!-- debug.html -->
</html>
```

Visiting `html.debug` (at `ZGVidWcuaHRtbA==` which is just it base64 encoded),
we get a page that says "testing rendering for flask app.py".

Trying to inspect the source code at app.py (`YXBwLnB5`), we get a result:

```python

from base64 import b64decode
import flask

app = flask.Flask(__name__)

@app.route('/<name>')
def index2(name):
    name = b64decode(name)
    if (validate(name)):
        return "This file is blocked!"
    try:
        file = open(name, 'r').read()
    except:
        return "File Not Found"
    return file

@app.route('/')
def index():
    return flask.redirect('/aW5kZXguaHRtbA==')

def validate(data):
    if data == b'flag.txt':
        return True
    return False


if __name__ == '__main__':
    app.run()
```

So, we can't just request `flag.txt` base64 encoded since thats hardcoded
blocked. Simply request `./flag.txt` (`Li9mbGFnLnR4dA==`).

Flag is `bctf{h4d_fun_w1th_my_l4st_m1nut3_w4rmuP????!}`.
