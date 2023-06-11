---
title: "hs CTF 2023"
description: "Writeups for problems solved by gp for the 2023 HS CTF competition."
date: 2023-06-08T09:24:19-05:00
url: "/ctfs/2023/hs-ctf-writeups"
type:
 - post
categories:
 - capture the flag writeups
tags:
 - ctfs
---

## Intro

> HSCTF is an international online hacking competition hosted by the WW-P HS
> North CS Club, designed to educate high schoolers in computer science. For
> more information, please check out our website and join our Discord server for
> updates!

## Solved

| Web                                                         | Misc                                | Rev                                 | Crypto                                            |
| ----------------------------------------------------------- | ----------------------------------- | ----------------------------------- | ------------------------------------------------- |
| [th3-w3bsite](#th3-w3bsite)                                 | [intro-to-netcat](#intro-to-netcat) | [back-to-basics](#back-to-basics)   | [double-trouble](#double-trouble)                 |
| [an-inaccessible-admin-panel](#an-inaccessible-admin-panel) |                                     | [brain-hurt](#brain-hurt)           | [really-small-algorithm](#really-small-algorithm) |
| [very-secure](#very-secure)                                 |                                     | [mystery-methods](#mystery-methods) | [cupcakes](#cupcakes)                             |
|                                                             |                                     | [keygen](#keygen)                   |                                                   |

### Web

#### th3-w3bsite

> It's a really simple w3bsite. Nothing much else to say. Be careful though.
>
> Link: https://th3-w3bsite.hsctf.com/

Opening the site, it looks like a simple HTML styled webpage. Viewing source,
the flag is in the comments:

```html
<!DOCTYPE html>
<!--Made by Alex Wang-->
<html>
  <head>
    <title>Th3 W3b-site</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
      body {
        margin: 0;
        padding: 0;
        font-family: Arial, sans-serif;
      }
      .hero {
        background-color: #ff8484;
        padding: 50px;
        background-size: cover;
        background-position: center;
        text-align: center;
        height: 100vh;
        display: flex;
        justify-content: center;
        align-items: center;
      }
      .hero-content {
        color: #000000;
        max-width: 800px;
        padding: 20px;
      }
      .footer {
        background-color: #333;
        color: #fff;
        text-align: center;
        padding: 20px;
      }
      .hero-image {
        width: 50%;
        height: auto;
      }
      /*Good stuff: http://tiny.cc/hsctfFlag*/
    </style>
  </head>
  <body>
    <div class="hero">
      <div class="hero-content">
        <h1>Welcome to th3 <a href= "http://tiny.cc/hsctfFlag">w3b-site</a></h1>
        <br>
        <div>Here you will find all the <a href="https://discord.com/invite/minecraft"> information </a> you need.</div>
        <br>
        <div>You probably won't get lost, but be careful just in case.</div>
        <br>
        <div>Here's an image of a cat:</div>
        <br>
        <img class="hero-image" src="https://images.unsplash.com/photo-1608848461950-0fe51dfc41cb?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MHxleHBsb3JlLWZlZWR8NHx8fGVufDB8fHx8&w=1000&q=80" alt="cat">
        <!-- Click here: http://losethegame.net/-->
    </div>
    </div>
    <div class="footer">
        <p>&copy; 2023 My Website.   <a href="http://tiny.cc/pentagonPapers"> All Rights Reserved. </a></p>
    </div>
  </body>
  <!-- flag{1434} -->
</html>
```

Flag is `flag{1434}`.

#### an-inaccessible-admin-panel

> The Joker is on the loose again in Gotham City! Police have found a web
> application where the Joker had allegedly tampered with. This mysterious web
> application has login page, but it has been behaving abnormally lately. Some
> time ago, an admin panel was created, but unfortunately, the password was lost
> to time. Unless you can find it...
>
> Can you prove that the Joker had tampered with the website?
>
> Default login info: Username: default Password: password123
>
> Link to login page: https://login-web-challenge.hsctf.com/

Navigating to that site and perusing the source code for the page, we see a link
to `login.js`:

```js
window.onload = function () {
  var loginForm = document.getElementById("loginForm");
  loginForm.addEventListener("submit", function (event) {
    event.preventDefault();

    var username = document.getElementById("username").value;
    var password = document.getElementById("password").value;

    function fii(num) {
      return num / 2 + fee(num);
    }
    function fee(num) {
      return foo(num * 5, square(num));
    }
    function foo(x, y) {
      return x * x + y * y + 2 * x * y;
    }
    function square(num) {
      return num * num;
    }

    var key = [
      32421672.5,
      160022555,
      197009354,
      184036413,
      165791431.5,
      110250050,
      203747134.5,
      106007665.5,
      114618486.5,
      1401872,
      20702532.5,
      1401872,
      37896374,
      133402552.5,
      197009354,
      197009354,
      148937670,
      114618486.5,
      1401872,
      20702532.5,
      160022555,
      97891284.5,
      184036413,
      106007665.5,
      128504948,
      232440576.5,
      4648358,
      1401872,
      58522542.5,
      171714872,
      190440057.5,
      114618486.5,
      197009354,
      1401872,
      55890618,
      128504948,
      114618486.5,
      1401872,
      26071270.5,
      190440057.5,
      197009354,
      97891284.5,
      101888885,
      148937670,
      133402552.5,
      190440057.5,
      128504948,
      114618486.5,
      110250050,
      1401872,
      44036535.5,
      184036413,
      110250050,
      114618486.5,
      184036413,
      4648358,
      1401872,
      20702532.5,
      160022555,
      110250050,
      1401872,
      26071270.5,
      210656255,
      114618486.5,
      184036413,
      232440576.5,
      197009354,
      128504948,
      133402552.5,
      160022555,
      123743427.5,
      1401872,
      21958629,
      114618486.5,
      106007665.5,
      165791431.5,
      154405530.5,
      114618486.5,
      190440057.5,
      1401872,
      23271009.5,
      128504948,
      97891284.5,
      165791431.5,
      190440057.5,
      1572532.5,
      1572532.5,
    ];

    function validatePassword(password) {
      var encryption = password.split("").map(function (char) {
        return char.charCodeAt(0);
      });
      var checker = [];
      for (var i = 0; i < encryption.length; i++) {
        var a = encryption[i];
        var b = fii(a);
        checker.push(b);
      }
      console.log(checker);

      if (key.length !== checker.length) {
        return false;
      }

      for (var i = 0; i < key.length; i++) {
        if (key[i] !== checker[i]) {
          return false;
        }
      }
      return true;
    }

    if (username === "Admin" && validatePassword(password)) {
      alert("Login successful. Redirecting to admin panel...");
      window.location.href = "admin_panel.html";
    } else if (username === "default" && password === "password123") {
      var websiteNames = [
        "Google",
        "YouTube",
        "Minecraft",
        "Discord",
        "Twitter",
      ];
      var websiteURLs = [
        "https://www.google.com",
        "https://www.youtube.com",
        "https://www.minecraft.net",
        "https://www.discord.com",
        "https://www.twitter.com",
      ];
      var randomNum = Math.floor(Math.random() * websiteNames.length);
      alert(
        "Login successful. Redirecting to " + websiteNames[randomNum] + "...",
      );
      window.location.href = websiteURLs[randomNum];
    } else {
      alert("Invalid credentials. Please try again.");
    }
  });
};
```

So, it looks like we need to reverse the `validatePassword` method. We know the
user (Admin), its just a matter of reversing the "encryption".

I chose to do so in Python, bc I hate JS.

```python
#!/usr/bin/env python

from string import printable

def square(num):
    return num*num

def foo(x, y):
    return x*x + y*y + 2*x*y

def fee(num):
    return foo(num * 5, square(num))

def fii(num):
    return num / 2 + fee(num)

key = [32421672.5, 160022555, 197009354, 184036413, 165791431.5, 110250050, 203747134.5, 106007665.5, 114618486.5, 1401872, 20702532.5, 1401872, 37896374, 133402552.5, 197009354, 197009354, 148937670, 114618486.5, 1401872, 20702532.5, 160022555, 97891284.5, 184036413, 106007665.5, 128504948, 232440576.5, 4648358, 1401872, 58522542.5, 171714872, 190440057.5, 114618486.5, 197009354, 1401872, 55890618, 128504948, 114618486.5, 1401872, 26071270.5, 190440057.5, 197009354, 97891284.5, 101888885, 148937670, 133402552.5, 190440057.5, 128504948, 114618486.5, 110250050, 1401872, 44036535.5, 184036413, 110250050, 114618486.5, 184036413, 4648358, 1401872, 20702532.5, 160022555, 110250050, 1401872, 26071270.5, 210656255, 114618486.5, 184036413, 232440576.5, 197009354, 128504948, 133402552.5, 160022555, 123743427.5, 1401872, 21958629, 114618486.5, 106007665.5, 165791431.5, 154405530.5, 114618486.5, 190440057.5, 1401872, 23271009.5, 128504948, 97891284.5, 165791431.5, 190440057.5, 1572532.5, 1572532.5];

for val in key:
    for maybe_char in printable:
        if fii(ord(maybe_char)) == val:
            print(maybe_char, end="")
```

Doing so gives

```text
Introduce A Little Anarchy, Upset The Established Order, And Everything Becomes Chaos!!
```

Logging in with that and user "Admin" gives the flag.

Flag is
`flag{Admin, Introduce A Little Anarchy, Upset The Established Order, And Everything Becomes Chaos!!}`.

#### very-secure

> this website is obviously 100% secure
>
> http://very-secure.hsctf.com/

Summary: Given source code leaks secret key is only 2 random bytes. Brute force
wordlist of all possible keys using `flask-unsign`.

Generate the wordlist:

```python
>>> with open("bytes.txt", "wb") as outfile:
...   for b in range(0xFF):
...     for b2 in range(0xFF):
...       outfile.write(bytes([b])+bytes([b2]))
...       outfile.write(b"\n")
```

Then brute force the key (grab a cookie via `curl -v`):

```text
flask-unsign -u -c eyJuYW1lIjoidXNlciJ9.ZH3cKg.CswCZIq-a42bBOG5NArg3k6X7pw  --wordlist bytes.txt --no-literal-eval
```

Gives "p6" as the key. Then just generate a new cookie:

```text
flask-unsign --sign -c '{"name":"admin"}' --secret 'p6' --legacy
eyJuYW1lIjoiYWRtaW4ifQ.ZH3cOA.NUfarqoPU5Yhwj9jzxdYQ_L48ws
```

Copy+paste that as the session cookie, and then reload the `/flag` and it gives
us the flag.

Flag is `flag{h0w_d1d_y0u_cr4ck_th3_k3y??}`.

### misc

#### intro-to-netcat

> `nc intro-to-netcat.hsctf.com 1337`
>
> How to install netcat: For Windows: https://nmap.org/ncat/
>
> For Mac: comes pre-installed
>
> For Linux: use your package manager

Connect to the endpoint in the description and it prints the flag.

Flag is `flag{netcat_is_cool}`.

### rev

#### back-to-basics

> Try to solve it with your eyes closed
>
> Attached file: ReverseEngineeringChallenge.java

The attached file is un-obfuscated Java:

```java
import java.util.Scanner;
class ReverseEngineeringChallenge {
    public static void main(String args[]) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter password: ");
        String userInput = scanner.next();
        if (checkPassword(userInput)) {
            System.out.println("Access granted.");
        } else {
            System.out.println("Access denied!");
        }
    }
    public static boolean checkPassword(String password) {
        return password.length() == 20 &&
                password.charAt(0) == 'f' &&
                password.charAt(11) == '_' &&
                password.charAt(1) == 'l' &&
                password.charAt(6) == '0' &&
                password.charAt(3) == 'g' &&
                password.charAt(8) == '1' &&
                password.charAt(4) == '{' &&
                password.charAt(9) == 'n' &&
                password.charAt(7) == 'd' &&
                password.charAt(10) == 'g' &&
                password.charAt(2) == 'a' &&
                password.charAt(12) == 'i' &&
                password.charAt(5) == 'c' &&
                password.charAt(17) == 'r' &&
                password.charAt(14) == '_' &&
                password.charAt(18) == 'd' &&
                password.charAt(16) == '4' &&
                password.charAt(19) == '}' &&
                password.charAt(15) == 'h' &&
                password.charAt(13) == '5';
    }
```

All we have to do is sort the `password.charAt` lines to get the flag.

Flag is `flag{c0d1ng_i5_h4rd}`.

#### brain-hurt

> Rumor has it Godzilla had a stroke trying to read the code
>
> Attached file: main.py

Attached is:

```python
import sys

def validate_flag(flag):
    encoded_flag = encode_flag(flag)
    expected_flag = 'ZT_YE\\0|akaY.LaLx0,aQR{"C'
    if encoded_flag == expected_flag:
        return True
    else:
        return False

def encode_flag(flag):
    encoded_flag = ""
    for c in flag:
        encoded_char = chr((ord(c) ^ 0xFF) % 95 + 32)
        encoded_flag += encoded_char
    return encoded_flag

def main():
    if len(sys.argv) != 2:
        print("Usage: python main.py <flag>")
        sys.exit(1)
    input_flag = sys.argv[1]
    if validate_flag(input_flag):
        print("Correct flag!")
    else:
        print("Incorrect flag.")

if __name__ == "__main__":
    main()
```

We can simply iterate over all printable chars and check if
`chr((ord(c) ^ 0xFF) % 95 + 32)` of that char matches the one in the encoded
flag. If so, its correct.

Flag is `flag{d1D_U_g3t_tH15_onE?}`.

#### mystery-methods

> vqx jung gb fnl urer
>
> Attached file: mysteryMethods.java

Attached:

```java
import java.util.Base64;
import java.util.Scanner;

public class mysteryMethods{
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Flag: ");
        String userInput = scanner.nextLine();
        String encryptedInput = encryptInput(userInput);

        if (checkFlag(encryptedInput)) {
            System.out.println("Correct flag! Congratulations!");
        } else {
            System.out.println("Incorrect flag! Please try again.");
        }
    }

    public static String encryptInput(String input) {
        String flag = input;
        flag = unknown2(flag, 345345345);
        flag = unknown1(flag);
        flag = unknown2(flag, 00000);
        flag = unknown(flag, 25);
        return flag;
    }

    public static boolean checkFlag(String encryptedInput) {
        return encryptedInput.equals("OS1QYj9VaEolaDgTSTXxSWj5Uj5JNVwRUT4vX290L1ondF1z");
    }

    public static String unknown(String input, int something) {
        StringBuilder result = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (Character.isLetter(c)) {
                char base = Character.isUpperCase(c) ? 'A' : 'a';
                int offset = (c - base + something) % 26;
                if (offset < 0) {
                    offset += 26;
                }
                c = (char) (base + offset);
            }
            result.append(c);
        }
        return result.toString();
    }

    public static String unknown1(String xyz) {
        return new StringBuilder(xyz).reverse().toString();
    }

    public static String unknown2(String xyz, int integer) {
        return Base64.getEncoder().encodeToString(xyz.getBytes());
    }
}
```

- `unknown2` is just base64
- `unknown1` just reverses the string
- `unknown` iterates over every char in the string, and

Once again, we can write some logic in Python to brute force all chars in the
alphabet, and work through them until we match the given output:

```python
#!/usr/bin/env python

from base64 import b64decode
from string import printable

enc = "OS1QYj9VaEolaDgTSTXxSWj5Uj5JNVwRUT4vX290L1ondF1z"
flag = ""

for char in enc:
    if not char.isalpha():
        flag += char
        continue

    for c in printable:
        if not c.isalpha():
            continue

        base = ord('A') if c.isupper() else ord('a')
        offset = (ord(c) - base + 25) % 26
        if offset < 0:
            offset += 26
        r = chr(base + offset)
        if r == char:
            flag+=c

print(flag)
print(b64decode(b64decode(flag)[::-1]))
```

Flag is `flag{hsCTF_I5_r3aLLy_fUN}`.

#### keygen

> A file: what's the key?
>
> Attached file: keygen

Keygen is a binary:

```
keygen: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=11a8b513cca3df3510555ecf1ffee22984bfe2af, for GNU/Linux 3.2.0, not stripped
```

Running it with input simply returns "Wrong" no matter what is given.

Normally, I use Ghidra for this kind of thing, but in redoing my CTF rig, I've
not setup Ghidra yet. So for this one, I grabbed the demo trial of Binary Ninja.

Opening the file in there, we see the following:

{{< image src="/img/CTFs/2023/hsctf/binja.png" alt="binary ninja overview of the keygen binary" position="center" style="border-radius: 8px;" >}}

So, all we need to do is give an input where every character xor'ed with `0xa`
matches the input char in the key (thing that ends in `:::w`).

More python:

```python
#!/usr/bin/env python

from string import printable

enc = "lfkmq<8=?=>?l\'==<2\'<;=>\'?l<i\'<l<9<h9l::::w"
print(len(enc))

flag = []
for char in enc:
    for c in printable:
        if (ord(c)^0xa) == ord(char):
            flag.append(c)
print(''.join(flag))
```

Flag is `flag{6275745f-7768-6174-5f6c-6f636b3f0000}`.

#### revrevrev

> Your friend is trying to pass this car game that he made. Sadly, they have
> long term memory loss and they don't remember the inputs or the goal of the
> game. All they have is the code. You should help them, as something hidden
> (like a flag?) will display if you find the correct inputs.
>
> Note: if you have a flag that works on the challenge file but isn't accepted,
> please DM the author (or another organizer).
>
> Attached file: revrevrev.py

Attached:

```python
ins = ""
while len(ins) != 20:
  ins = input("input a string of size 20: ")

s = 0
a = 0
x = 0
y = 0
for c in ins:
  if c == 'r': # rev
    s += 1
  elif c == 'L': # left
    a = (a + 1) % 4
  elif c == 'R': # right
    a = (a + 3) % 4
  else:
    print("this character is not necessary for the solution.")
  if a == 0:
    x += s
  elif a == 1:
    y += s
  elif a == 2:
    x -= s
  elif a == 3:
    y -= s
print((x, y))
if x == 168 and y == 32:
  print("flag{" + ins + "}")
else:
  print("incorrect sadly")
```

Brute forcing using itertools:

```python
#!/usr/bin/env python
import itertools

choices = ["r", "L", "R"]

flag = ["a"*20]

def find_flag(ins):
    s = 0
    a = 0
    x = 0
    y = 0
    for c in ins:
        if c == 'r': # rev
            s += 1
        elif c == 'L': # left
            a = (a + 1) % 4
        elif c == 'R': # right
            a = (a + 3) % 4
        else:
            print("this character is not necessary for the solution.")
        if a == 0:
            x += s
        elif a == 1:
            y += s
        elif a == 2:
            x -= s
        elif a == 3:
            y -= s

    if x == 168 and y == 32:
        print("flag{" + ins + "}")


def generate_strings(length=20):
    chars = choices
    for item in itertools.product(chars, repeat=length):
        yield "".join(item)


for f in generate_strings():
    find_flag(f)
```

Flag is `flag{rrrrrrrrrrrrrrrrLRLR}`.

#### micrurus-fulvius

> Micrurus fulvius, commonly known as the eastern coral snake, common coral
> snake, American cobra, and more, is a species of highly venomous coral snake
> in the family Elapidae. The species is endemic to the southeastern United
> States. It should not be confused with the scarlet snake (Cemophora coccinea)
> or scarlet kingsnake (Lampropeltis elapsoides), which are harmless mimics No
> subspecies are currently recognized.
>
> Attached file: micrurus-fulvius.pyc

Checking `file` on the attached .pyc file, we see its compiled Python 3.8
bytecode. So, we can use
[decompyle3](https://github.com/rocky/python-decompile3) to get the source.

With `decompyle3 micrurus-fulvius.pyc`:

```python
# decompyle3 version 3.9.0
# Python bytecode version base 3.8.0 (3413)
# Decompiled from: Python 3.9.16 (main, Jan 27 2023, 10:31:56)
# [GCC 11.3.0]
# Embedded file name: chall.py
# Compiled at: 2023-06-01 17:33:44
# Size of source mod 2**32: 644 bytes
from hashlib import sha256 as k

def a(n):
    b = 0
    while True:
        if n != 1:
            if n & 1:
                n *= 3
                n += 1
            else:
                n //= 2
            b += 1

    return b


def d(u, p):
    return (u << p % 5) - 158


def j(q, w):
    return ord(q) * 115 + ord(w) * 21


def t():
    x = input()
    l = [-153,462,438,1230,1062,-24,-210,54,2694,1254,69,-162,210,150]
    m = 'b4f9d505'
    if len(x) - 1 != len(l):
        return False
    for i, c in enumerate(zip(x, x[1:])):
        if d(a(j(*c) - 10), i) * 3 != l[i]:
            return False
    else:
        if k(x.encode()).hexdigest()[:8] != m:
            return False
        return True


def g():
    if t():
        print('Correct')
    else:
        print('Wrong')


if __name__ == '__main__':
    g()
# okay decompiling micrurus-fulvius.pyc
```

So, we need to give it something that is 14 chars long (to match the length of
l) that also satisfies the logic.

After some research, `a()` seems to be a take on the **Collatz Conjecture**:

> You are slightly misstating what is called the Collatz Conjecture.
>
> This states that if you start with any positive integer greater than 1, if the number is even, divide it by 2.
>
> If the number is odd, multiply it by 3 and add 1.
>
> Repeat this process.
>
> The conjecture states that you will eventually get to 1.

I couldn't get any further than this in the time I worked, though.

### crypto

#### double-trouble

The attached PDF is just text that says the following:

```text
___________ Salad: a green salad of romaine lettuce and croutons dressed with lemon juice, olive oil,
egg, Worcestershire sauce, anchovies, garlic, Dijon mustard, Parmesan cheese, and black pepper. In its
original form, this salad was prepared and served tableside.
Hvwg gvcizr bch ps hcc vofr.
Wb toqh, W kwzz uwjs wh hc mci fwuvh bck!
Hvs tzou wg hvs tczzckwbu:
OmqemdOubtqdeMdqOaax
Vcksjsf, wh wg sbqcrsr gc mci vojs hc rsqcrs wh twfgh!
Pkovovovovo
Fsasapsf, hvs tzou tcfaoh wg tzou{}
```

Which is clearly a reference to a Ceasar Cipher (or ROT13). Doing so with a ROT
of 12 gives us:

```text
This should not be too hard.
In fact, I will give it to you right now!
The flag is the following:
AycqypAgnfcpqYpcAmmj
However, it is encoded so you have to decode it first!
Bwahahahaha
Remember, the flag format is flag{}
```

Which then hitting that with a ROT of 2 gives

```text
CaesarCiphersAreCool
```

Flag is `flag{CaesarCiphersAreCool}`.

#### really-small-algorithm

> What do these numbers mean?
>
> n = 4155782502547623093831518113976094054382827573251453061239 e = 65537 c =
> 2669292279100633236493181205299328973407167118230741040683

RSA (really small algorithm). Really small n.
[FactorDB shows](http://www.factordb.com/index.php?query=4155782502547623093831518113976094054382827573251453061239):

```
FF	58 (show)	4155782502...39<58> = 63208845854086540220230493287<29> · 65746849928900354177936765297<29>
```

So we know:

```text
p = 63208845854086540220230493287
q = 65746849928900354177936765297
```

Now just plug into any RSA solver for the ct.

```python
from Crypto.PublicKey import RSA
from sympy.ntheory import factorint
# pip3.8 install factordb-pycli
from factordb.factordb import FactorDB

from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes

def check_factordb(N):
    factorized = FactorDB(N)
    factorized.connect()
    factor_list = factorized.get_factor_list()
    assert(len(factor_list) != 0 )
    return factor_list

def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
        gcd = b
    return gcd, x, y

def main():
    N = 4155782502547623093831518113976094054382827573251453061239
    e = 65537
    ct = 2669292279100633236493181205299328973407167118230741040683

    print("N: ", N)
    print("e: ", e)

    factors = check_factordb(N)
    if len(set(factors)) == 1 and len(factors) == 2:
        # p = q = sqrt(N)
        print(f"p = q = srqt(N) = {factors[0]}")
        phi = factors[0] * (factors[0] - 1)
    else:
        phi = 1
        for factor in factors:
            print(f"factor: {factor}")
            phi *= (factor-1)

    # Compute modular inverse of e
    gcd, d, b = egcd(e, phi)
    print("d:  " + str(d) );

    # Decrypt
    pt = pow(ct, d, N)
    print("Plaintext: ", pt)

if __name__=='__main__':
    main()
```

Gives

```text
python foo.py
N:  4155782502547623093831518113976094054382827573251453061239
e:  65537
factor: 63208845854086540220230493287
factor: 65746849928900354177936765297
d:  -270322120456543895036449055027394461490625460639815026271
Plaintext:  38321129010646098823796672289391232228923427525063293
```

Which we can convert to plaintext via:

```bash
function decimal_to_ascii(){ local decimal=$1
    echo "obase=16; $decimal" | bc  | xxd -r -p; echo ""
}

decimal_to_ascii 38321129010646098823796672289391232228923427525063293
flag{bigger_is_better}
```

Flag is `flag{bigger_is_better}`.

#### cupcakes

> You have to make 100 cupcakes for your upcoming end of year party and you only
> have 3 hours to do so after oversleeping the night before. However you are in
> luck because ShopRite just released their Magic Flour that makes any sort of
> batter immediately. In order to get the Magic Flour you have to solve a puzzle
> where you decode the message "avxmsvyusbyxj" using the key word SIFT. Time is
> ticking!
>
> Note: wrap the result you get in the flag format in all lowercase, eg.
> flag{example}

Vigenere with key "SIFT".

https://gchq.github.io/CyberChef/#recipe=Vigen%C3%A8re_Decode('SIFT')&input=YXZ4bXN2eXVzYnl4ag

Flag is `flag{instantbatter}`.
