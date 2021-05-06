---
title: "AMD 6800xt Haschat Benchmark"
date: 2021-05-05T09:24:55-05:00
categories:
 - Cracking
---

## Info

Kernel:

```
uname -r
5.12.1-051201-generic
```

Release:

```
lsb_release -a
No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu 20.04.2 LTS
Release:	20.04
Codename:	focal
```
Relevant lscpi:

```
2f:00.0 VGA compatible controller: Advanced Micro Devices, Inc. [AMD/ATI] Device 73bf (rev c1)
	Subsystem: Tul Corporation / PowerColor Device 2406
	Kernel driver in use: amdgpu
	Kernel modules: amdgpu
```

Hashcat:

```
hashcat --version
v6.1.1-318-gf011f790e
```

amdgpu version:
* `amdgpu-pro-21.10-1247438-ubuntu-20.04`

## Setup

1. Uninstalled previous/existing amdgpu installation
2. Update kernel to latest mainline (5.12.1-051201-generic at the time)
3. reboot
4. apt update packages + unsure installed latest headers + `sudo apt --fix-broken install` to fix some things played with before hand

  ```bash
  sudo apt update
  sudo apt install linux-headers-$(uname -r)
  sudo apt --fix-broken install              
  ```
5. Install latest amdgpu:

  ```bash
  ./amdgpu-install --no-dkms -y --opencl=rocr,legacy
  ```
6. Fetch + build + install latest [haschat source](https://github.com/hashcat/hashcat).

## Card

[Red Dragon AMD Radeon™ RX 6800 XT 16GB GDDR6 -- RADEON RX 6800 XT](https://www.powercolor.com/product?id=1606116634).

## AMD 6800xt Haschat Benchmark

Standard:

```
hashcat -b
hashcat (v6.1.1-318-gf011f790e) starting in benchmark mode...

Benchmarking uses hand-optimized kernel code by default.
You can use it in your cracking session by setting the -O option.
Note: Using optimized kernel code limits the maximum supported password length.
To disable the optimized kernel code in benchmark mode, use the -w option.

OpenCL API (OpenCL 2.0 AMD-APP (3246.0)) - Platform #1 [Advanced Micro Devices, Inc.]
=====================================================================================
* Device #1: gfx1030, 16256/16368 MB (13912 MB allocatable), 36MCU

Benchmark relevant options:
===========================
* --optimized-kernel-enable

Hashmode: 0 - MD5

Speed.#1.........: 52801.7 MH/s (45.58ms) @ Accel:1024 Loops:1024 Thr:64 Vec:1

Hashmode: 100 - SHA1

Speed.#1.........: 20716.0 MH/s (58.04ms) @ Accel:1024 Loops:512 Thr:64 Vec:1

Hashmode: 1400 - SHA2-256

Speed.#1.........:  8772.1 MH/s (68.60ms) @ Accel:256 Loops:1024 Thr:64 Vec:1

Hashmode: 1700 - SHA2-512

Speed.#1.........:  2357.2 MH/s (63.80ms) @ Accel:128 Loops:512 Thr:64 Vec:1

Hashmode: 22000 - WPA-PBKDF2-PMKID+EAPOL (Iterations: 4095)

Speed.#1.........:  1061.4 kH/s (69.07ms) @ Accel:256 Loops:512 Thr:64 Vec:1

Hashmode: 1000 - NTLM

Speed.#1.........: 86373.3 MH/s (27.74ms) @ Accel:1024 Loops:1024 Thr:64 Vec:1

Hashmode: 3000 - LM

Speed.#1.........: 52478.5 MH/s (45.53ms) @ Accel:1024 Loops:1024 Thr:64 Vec:1

Hashmode: 5500 - NetNTLMv1 / NetNTLMv1+ESS

Speed.#1.........: 57674.9 MH/s (41.65ms) @ Accel:1024 Loops:1024 Thr:64 Vec:1

Hashmode: 5600 - NetNTLMv2

Speed.#1.........:  3533.1 MH/s (85.17ms) @ Accel:512 Loops:256 Thr:64 Vec:1

Hashmode: 1500 - descrypt, DES (Unix), Traditional DES

Speed.#1.........:  1913.0 MH/s (78.62ms) @ Accel:64 Loops:1024 Thr:64 Vec:1

Hashmode: 500 - md5crypt, MD5 (Unix), Cisco-IOS $1$ (MD5) (Iterations: 1000)

Speed.#1.........: 21706.1 kH/s (51.38ms) @ Accel:1024 Loops:500 Thr:64 Vec:1

Hashmode: 3200 - bcrypt $2*$, Blowfish (Unix) (Iterations: 32)

Speed.#1.........:    56239 H/s (35.19ms) @ Accel:128 Loops:32 Thr:16 Vec:1

Hashmode: 1800 - sha512crypt $6$, SHA512 (Unix) (Iterations: 5000)

Speed.#1.........:   287.6 kH/s (50.81ms) @ Accel:128 Loops:256 Thr:64 Vec:1

Hashmode: 7500 - Kerberos 5, etype 23, AS-REQ Pre-Auth

Speed.#1.........:   858.5 MH/s (87.73ms) @ Accel:256 Loops:128 Thr:64 Vec:1

Hashmode: 13100 - Kerberos 5, etype 23, TGS-REP

Speed.#1.........:   823.1 MH/s (91.45ms) @ Accel:512 Loops:64 Thr:64 Vec:1

Hashmode: 15300 - DPAPI masterkey file v1 (Iterations: 23999)

Speed.#1.........:   180.9 kH/s (67.69ms) @ Accel:128 Loops:1024 Thr:64 Vec:1

Hashmode: 15900 - DPAPI masterkey file v2 (Iterations: 12899)

Speed.#1.........:    80534 H/s (71.59ms) @ Accel:128 Loops:256 Thr:64 Vec:1

Hashmode: 7100 - macOS v10.8+ (PBKDF2-SHA512) (Iterations: 1023)

Speed.#1.........:  1012.2 kH/s (64.25ms) @ Accel:256 Loops:127 Thr:64 Vec:1

Hashmode: 11600 - 7-Zip (Iterations: 16384)

Speed.#1.........:  1099.4 kH/s (63.39ms) @ Accel:128 Loops:4096 Thr:64 Vec:1

Hashmode: 12500 - RAR3-hp (Iterations: 262144)

Speed.#1.........:   139.5 kH/s (65.65ms) @ Accel:64 Loops:16384 Thr:64 Vec:1

Hashmode: 13000 - RAR5 (Iterations: 32799)

Speed.#1.........:   111.4 kH/s (80.01ms) @ Accel:128 Loops:1024 Thr:64 Vec:1

Hashmode: 6211 - TrueCrypt RIPEMD160 + XTS 512 bit (Iterations: 1999)

Speed.#1.........:   664.6 kH/s (54.78ms) @ Accel:256 Loops:128 Thr:64 Vec:1

Hashmode: 13400 - KeePass 1 (AES/Twofish) and KeePass 2 (AES) (Iterations: 24569)

Speed.#1.........:    86429 H/s (284.09ms) @ Accel:256 Loops:1024 Thr:64 Vec:1

Hashmode: 6800 - LastPass + LastPass sniffed (Iterations: 499)

Speed.#1.........:  7087.4 kH/s (53.21ms) @ Accel:512 Loops:249 Thr:64 Vec:1

Hashmode: 11300 - Bitcoin/Litecoin wallet.dat (Iterations: 200459)

Speed.#1.........:    10838 H/s (69.33ms) @ Accel:64 Loops:1024 Thr:64 Vec:1

Started: Wed May  5 17:47:25 2021
Stopped: Wed May  5 17:51:32 2021
```

benchmark-all:

1. Random issue with:

```
Hashmode: 1100 - Domain Cached Credentials (DCC), MS Cache

* Device #1: ATTENTION! OpenCL kernel self-test failed.

Your device driver installation is probably broken.
See also: https://hashcat.net/faq/wrongdriver

```

2. Originally, died on

```
* Device #1: Skipping hash-mode 17200 - known CUDA/OpenCL Runtime/Driver issue (not a hashcat issue)
             You can use --force to override, but do not report related errors.
```

so re-ran full suite with the `--force` flag.


```none
hashcat (v6.1.1-318-gf011f790e) starting in benchmark mode...

[33mBenchmarking uses hand-optimized kernel code by default.[0m
[33mYou can use it in your cracking session by setting the -O option.[0m
[33mNote: Using optimized kernel code limits the maximum supported password length.[0m
[33mTo disable the optimized kernel code in benchmark mode, use the -w option.[0m
[33m[0m
[33mYou have enabled --force to bypass dangerous warnings and errors![0m
[33mThis can hide serious problems and should only be done when debugging.[0m
[33mDo not report hashcat issues encountered when using --force.[0m
OpenCL API (OpenCL 2.0 AMD-APP (3246.0)) - Platform #1 [Advanced Micro Devices, Inc.]
=====================================================================================
* Device #1: gfx1030, 16256/16368 MB (13912 MB allocatable), 36MCU

Benchmark relevant options:
===========================
* --benchmark-all
* --force
* --optimized-kernel-enable

Hashmode: 0 - MD5

Speed.#1.........: 52491.9 MH/s (45.75ms) @ Accel:1024 Loops:1024 Thr:64 Vec:1

Hashmode: 10 - md5($pass.$salt)

Speed.#1.........: 52432.3 MH/s (45.77ms) @ Accel:1024 Loops:1024 Thr:64 Vec:1

Hashmode: 11 - Joomla < 2.5.18

Speed.#1.........: 52090.9 MH/s (46.10ms) @ Accel:1024 Loops:1024 Thr:64 Vec:1

Hashmode: 12 - PostgreSQL

Speed.#1.........: 52111.5 MH/s (46.21ms) @ Accel:1024 Loops:1024 Thr:64 Vec:1

Hashmode: 20 - md5($salt.$pass)

Speed.#1.........: 26774.2 MH/s (90.04ms) @ Accel:1024 Loops:1024 Thr:64 Vec:1

Hashmode: 21 - osCommerce, xt:Commerce

Speed.#1.........: 26708.8 MH/s (90.24ms) @ Accel:1024 Loops:1024 Thr:64 Vec:1

Hashmode: 22 - Juniper NetScreen/SSG (ScreenOS)

Speed.#1.........: 27234.0 MH/s (88.53ms) @ Accel:1024 Loops:1024 Thr:64 Vec:1

Hashmode: 23 - Skype

Speed.#1.........: 26944.1 MH/s (89.43ms) @ Accel:1024 Loops:1024 Thr:64 Vec:1

Hashmode: 24 - SolarWinds Serv-U

Speed.#1.........: 26817.9 MH/s (89.88ms) @ Accel:1024 Loops:1024 Thr:64 Vec:1

Hashmode: 30 - md5(utf16le($pass).$salt)

Speed.#1.........: 51907.8 MH/s (46.38ms) @ Accel:1024 Loops:1024 Thr:64 Vec:1

Hashmode: 40 - md5($salt.utf16le($pass))

Speed.#1.........: 26960.7 MH/s (89.45ms) @ Accel:1024 Loops:1024 Thr:64 Vec:1

Hashmode: 50 - HMAC-MD5 (key = $pass)

Speed.#1.........:  8020.3 MH/s (75.10ms) @ Accel:1024 Loops:256 Thr:64 Vec:1

Hashmode: 60 - HMAC-MD5 (key = $salt)

Speed.#1.........: 15893.7 MH/s (75.78ms) @ Accel:1024 Loops:512 Thr:64 Vec:1

Hashmode: 100 - SHA1

Speed.#1.........: 20466.1 MH/s (58.80ms) @ Accel:1024 Loops:512 Thr:64 Vec:1

Hashmode: 101 - nsldap, SHA-1(Base64), Netscape LDAP SHA

Speed.#1.........: 20536.1 MH/s (58.60ms) @ Accel:1024 Loops:512 Thr:64 Vec:1

Hashmode: 110 - sha1($pass.$salt)

Speed.#1.........: 20669.5 MH/s (58.20ms) @ Accel:1024 Loops:512 Thr:64 Vec:1

Hashmode: 111 - nsldaps, SSHA-1(Base64), Netscape LDAP SSHA

Speed.#1.........: 20554.2 MH/s (58.53ms) @ Accel:512 Loops:1024 Thr:64 Vec:1

Hashmode: 112 - Oracle S: Type (Oracle 11+)

Speed.#1.........: 20708.9 MH/s (58.13ms) @ Accel:512 Loops:1024 Thr:64 Vec:1

Hashmode: 120 - sha1($salt.$pass)

Speed.#1.........: 16124.1 MH/s (74.71ms) @ Accel:512 Loops:1024 Thr:64 Vec:1

Hashmode: 121 - SMF (Simple Machines Forum) > v1.1

Speed.#1.........: 16128.8 MH/s (74.68ms) @ Accel:1024 Loops:512 Thr:64 Vec:1

Hashmode: 122 - macOS v10.4, macOS v10.5, MacOS v10.6

Speed.#1.........: 16092.7 MH/s (74.69ms) @ Accel:512 Loops:1024 Thr:64 Vec:1

Hashmode: 124 - Django (SHA-1)

Speed.#1.........: 16089.1 MH/s (74.79ms) @ Accel:512 Loops:1024 Thr:64 Vec:1

Hashmode: 125 - ArubaOS

Speed.#1.........: 16104.1 MH/s (74.77ms) @ Accel:512 Loops:1024 Thr:64 Vec:1

Hashmode: 130 - sha1(utf16le($pass).$salt)

Speed.#1.........: 20660.7 MH/s (58.16ms) @ Accel:512 Loops:1024 Thr:64 Vec:1

Hashmode: 131 - MSSQL (2000)

Speed.#1.........: 20627.7 MH/s (58.14ms) @ Accel:1024 Loops:512 Thr:64 Vec:1

Hashmode: 132 - MSSQL (2005)

Speed.#1.........: 20673.5 MH/s (58.20ms) @ Accel:1024 Loops:512 Thr:64 Vec:1

Hashmode: 133 - PeopleSoft

Speed.#1.........: 20481.7 MH/s (58.55ms) @ Accel:512 Loops:1024 Thr:64 Vec:1

Hashmode: 140 - sha1($salt.utf16le($pass))

Speed.#1.........: 16099.8 MH/s (74.81ms) @ Accel:1024 Loops:512 Thr:64 Vec:1

Hashmode: 141 - Episerver 6.x < .NET 4

Speed.#1.........: 16060.5 MH/s (74.86ms) @ Accel:512 Loops:1024 Thr:64 Vec:1

Hashmode: 150 - HMAC-SHA1 (key = $pass)

Speed.#1.........:  4689.0 MH/s (64.16ms) @ Accel:256 Loops:512 Thr:64 Vec:1

Hashmode: 160 - HMAC-SHA1 (key = $salt)

Speed.#1.........:  8776.3 MH/s (68.46ms) @ Accel:256 Loops:1024 Thr:64 Vec:1

Hashmode: 200 - MySQL323

Speed.#1.........:   133.6 GH/s (17.95ms) @ Accel:1024 Loops:1024 Thr:64 Vec:1

Hashmode: 300 - MySQL4.1/MySQL5

Speed.#1.........:  9120.4 MH/s (65.96ms) @ Accel:512 Loops:512 Thr:64 Vec:1

Hashmode: 400 - phpass (Iterations: 2048)

Speed.#1.........: 14993.8 kH/s (75.41ms) @ Accel:1024 Loops:1024 Thr:64 Vec:1

Hashmode: 500 - md5crypt, MD5 (Unix), Cisco-IOS $1$ (MD5) (Iterations: 1000)

Speed.#1.........: 21510.3 kH/s (51.96ms) @ Accel:1024 Loops:500 Thr:64 Vec:1

Hashmode: 501 - Juniper IVE (Iterations: 1000)

Speed.#1.........: 21524.6 kH/s (51.92ms) @ Accel:1024 Loops:500 Thr:64 Vec:1

Hashmode: 600 - BLAKE2b-512

Speed.#1.........:  4785.6 MH/s (62.87ms) @ Accel:256 Loops:512 Thr:64 Vec:1

Hashmode: 900 - MD4

Speed.#1.........: 84878.3 MH/s (28.17ms) @ Accel:1024 Loops:1024 Thr:64 Vec:1

Hashmode: 1000 - NTLM

Speed.#1.........: 85238.0 MH/s (28.08ms) @ Accel:1024 Loops:1024 Thr:64 Vec:1

Hashmode: 1100 - Domain Cached Credentials (DCC), MS Cache

[33mYour device driver installation is probably broken.[0m
[33mSee also: https://hashcat.net/faq/wrongdriver[0m
[33m[0m
Speed.#1.........: 29001.5 MH/s (82.95ms) @ Accel:1024 Loops:1024 Thr:64 Vec:1

Hashmode: 1300 - SHA2-224

Speed.#1.........:  8502.2 MH/s (70.84ms) @ Accel:256 Loops:1024 Thr:64 Vec:1

Hashmode: 1400 - SHA2-256

Speed.#1.........:  8677.2 MH/s (69.40ms) @ Accel:512 Loops:512 Thr:64 Vec:1

Hashmode: 1410 - sha256($pass.$salt)

Speed.#1.........:  8692.9 MH/s (69.27ms) @ Accel:256 Loops:1024 Thr:64 Vec:1

Hashmode: 1411 - SSHA-256(Base64), LDAP {SSHA256}

Speed.#1.........:  8672.5 MH/s (69.37ms) @ Accel:256 Loops:1024 Thr:64 Vec:1

Hashmode: 1420 - sha256($salt.$pass)

Speed.#1.........:  7832.3 MH/s (76.81ms) @ Accel:256 Loops:1024 Thr:64 Vec:1

Hashmode: 1421 - hMailServer

Speed.#1.........:  7830.4 MH/s (76.93ms) @ Accel:256 Loops:1024 Thr:64 Vec:1

Hashmode: 1430 - sha256(utf16le($pass).$salt)

Speed.#1.........:  8703.4 MH/s (69.21ms) @ Accel:256 Loops:1024 Thr:64 Vec:1

Hashmode: 1440 - sha256($salt.utf16le($pass))

Speed.#1.........:  7818.2 MH/s (76.87ms) @ Accel:512 Loops:512 Thr:64 Vec:1

Hashmode: 1441 - Episerver 6.x >= .NET 4

Speed.#1.........:  7818.4 MH/s (76.96ms) @ Accel:256 Loops:1024 Thr:64 Vec:1

Hashmode: 1450 - HMAC-SHA256 (key = $pass)

Speed.#1.........:  1707.7 MH/s (88.23ms) @ Accel:128 Loops:512 Thr:64 Vec:1

Hashmode: 1460 - HMAC-SHA256 (key = $salt)

Speed.#1.........:  3721.4 MH/s (80.77ms) @ Accel:128 Loops:1024 Thr:64 Vec:1

Hashmode: 1500 - descrypt, DES (Unix), Traditional DES

Speed.#1.........:  1895.9 MH/s (79.34ms) @ Accel:64 Loops:1024 Thr:64 Vec:1

Hashmode: 1600 - Apache $apr1$ MD5, md5apr1, MD5 (APR) (Iterations: 1000)

Speed.#1.........: 21570.8 kH/s (51.82ms) @ Accel:1024 Loops:500 Thr:64 Vec:1

Hashmode: 1700 - SHA2-512

Speed.#1.........:  2327.8 MH/s (64.60ms) @ Accel:64 Loops:1024 Thr:64 Vec:1

Hashmode: 1710 - sha512($pass.$salt)

Speed.#1.........:  2061.1 MH/s (73.01ms) @ Accel:128 Loops:512 Thr:64 Vec:1

Hashmode: 1711 - SSHA-512(Base64), LDAP {SSHA512}

Speed.#1.........:  2053.6 MH/s (73.33ms) @ Accel:64 Loops:1024 Thr:64 Vec:1

Hashmode: 1720 - sha512($salt.$pass)

Speed.#1.........:  2225.7 MH/s (67.65ms) @ Accel:128 Loops:512 Thr:64 Vec:1

Hashmode: 1722 - macOS v10.7

Speed.#1.........:  2224.5 MH/s (67.62ms) @ Accel:256 Loops:256 Thr:64 Vec:1

Hashmode: 1730 - sha512(utf16le($pass).$salt)

Speed.#1.........:  2053.0 MH/s (73.35ms) @ Accel:64 Loops:1024 Thr:64 Vec:1

Hashmode: 1731 - MSSQL (2012, 2014)

Speed.#1.........:  2061.2 MH/s (73.01ms) @ Accel:256 Loops:256 Thr:64 Vec:1

Hashmode: 1740 - sha512($salt.utf16le($pass))

Speed.#1.........:  2032.2 MH/s (74.10ms) @ Accel:64 Loops:1024 Thr:64 Vec:1

Hashmode: 1750 - HMAC-SHA512 (key = $pass)

Speed.#1.........:   503.0 MH/s (74.88ms) @ Accel:256 Loops:64 Thr:64 Vec:1

Hashmode: 1760 - HMAC-SHA512 (key = $salt)

Speed.#1.........:  1026.1 MH/s (73.34ms) @ Accel:64 Loops:512 Thr:64 Vec:1

Hashmode: 1800 - sha512crypt $6$, SHA512 (Unix) (Iterations: 5000)

Speed.#1.........:   283.4 kH/s (51.58ms) @ Accel:128 Loops:256 Thr:64 Vec:1

Hashmode: 2000 - STDOUT

Speed.#1.........: 21794.3 GH/s (0.02ms) @ Accel:1024 Loops:1024 Thr:64 Vec:1

Hashmode: 2100 - Domain Cached Credentials 2 (DCC2), MS Cache 2 (Iterations: 10239)

Speed.#1.........:   841.9 kH/s (69.75ms) @ Accel:512 Loops:512 Thr:64 Vec:1

Hashmode: 2400 - Cisco-PIX MD5

Speed.#1.........: 34654.1 MH/s (69.38ms) @ Accel:1024 Loops:1024 Thr:64 Vec:1

Hashmode: 2410 - Cisco-ASA MD5

Speed.#1.........: 34557.3 MH/s (69.66ms) @ Accel:1024 Loops:1024 Thr:64 Vec:1

Hashmode: 2500 - WPA-EAPOL-PBKDF2 (Iterations: 4095)

Speed.#1.........:  1045.9 kH/s (69.96ms) @ Accel:256 Loops:512 Thr:64 Vec:1

Hashmode: 2501 - WPA-EAPOL-PMK (Iterations: 0)

Speed.#1.........:   408.0 MH/s (0.00ms) @ Accel:1024 Loops:1024 Thr:64 Vec:1

Hashmode: 2600 - md5(md5($pass))

Speed.#1.........: 15429.0 MH/s (77.96ms) @ Accel:1024 Loops:512 Thr:64 Vec:1

Hashmode: 2611 - vBulletin < v3.8.5

Speed.#1.........: 15435.2 MH/s (78.01ms) @ Accel:1024 Loops:512 Thr:64 Vec:1

Hashmode: 2612 - PHPS

Speed.#1.........: 15415.2 MH/s (78.11ms) @ Accel:1024 Loops:512 Thr:64 Vec:1

Hashmode: 2711 - vBulletin >= v3.8.5

Speed.#1.........: 10484.4 MH/s (57.35ms) @ Accel:1024 Loops:256 Thr:64 Vec:1

Hashmode: 2811 - MyBB 1.2+, IPB2+ (Invision Power Board)

Speed.#1.........: 10853.5 MH/s (55.42ms) @ Accel:1024 Loops:256 Thr:64 Vec:1

Hashmode: 3000 - LM

Speed.#1.........: 51824.7 MH/s (46.20ms) @ Accel:1024 Loops:1024 Thr:64 Vec:1

Hashmode: 3100 - Oracle H: Type (Oracle 7+)

Speed.#1.........:  1187.5 MH/s (63.37ms) @ Accel:32 Loops:1024 Thr:64 Vec:1

Hashmode: 3200 - bcrypt $2*$, Blowfish (Unix) (Iterations: 32)

Speed.#1.........:    56187 H/s (35.26ms) @ Accel:128 Loops:32 Thr:16 Vec:1

Hashmode: 3710 - md5($salt.md5($pass))

Speed.#1.........: 14114.3 MH/s (85.38ms) @ Accel:1024 Loops:512 Thr:64 Vec:1

Hashmode: 3711 - MediaWiki B type

Speed.#1.........: 14052.4 MH/s (85.56ms) @ Accel:1024 Loops:512 Thr:64 Vec:1

Hashmode: 3800 - md5($salt.$pass.$salt)

Speed.#1.........: 26709.1 MH/s (90.22ms) @ Accel:1024 Loops:1024 Thr:64 Vec:1

Hashmode: 3910 - md5(md5($pass).md5($salt))

Speed.#1.........: 10483.7 MH/s (57.38ms) @ Accel:1024 Loops:256 Thr:64 Vec:1

Hashmode: 4010 - md5($salt.md5($salt.$pass))

Speed.#1.........: 12455.6 MH/s (96.59ms) @ Accel:1024 Loops:512 Thr:64 Vec:1

Hashmode: 4110 - md5($salt.md5($pass.$salt))

Speed.#1.........: 14019.6 MH/s (85.84ms) @ Accel:1024 Loops:512 Thr:64 Vec:1

Hashmode: 4300 - md5(strtoupper(md5($pass)))

Speed.#1.........: 15404.0 MH/s (78.21ms) @ Accel:1024 Loops:512 Thr:64 Vec:1

Hashmode: 4400 - md5(sha1($pass))

Speed.#1.........: 10547.2 MH/s (56.89ms) @ Accel:1024 Loops:256 Thr:64 Vec:1

Hashmode: 4500 - sha1(sha1($pass))

Speed.#1.........:  8301.0 MH/s (72.36ms) @ Accel:512 Loops:512 Thr:64 Vec:1

Hashmode: 4510 - sha1(sha1($pass).$salt)

Speed.#1.........:  7999.2 MH/s (75.30ms) @ Accel:512 Loops:512 Thr:64 Vec:1

Hashmode: 4520 - sha1($salt.sha1($pass))

Speed.#1.........:  5112.4 MH/s (58.89ms) @ Accel:256 Loops:512 Thr:64 Vec:1

Hashmode: 4521 - Redmine

Speed.#1.........:  5111.1 MH/s (58.88ms) @ Accel:512 Loops:256 Thr:64 Vec:1

Hashmode: 4522 - PunBB

Speed.#1.........:  7680.2 MH/s (78.29ms) @ Accel:512 Loops:512 Thr:64 Vec:1

Hashmode: 4700 - sha1(md5($pass))

Speed.#1.........: 10879.8 MH/s (55.14ms) @ Accel:512 Loops:512 Thr:64 Vec:1

Hashmode: 4710 - sha1(md5($pass).$salt)

Speed.#1.........: 10346.8 MH/s (58.13ms) @ Accel:512 Loops:512 Thr:64 Vec:1

Hashmode: 4711 - Huawei sha1(md5($pass).$salt)

Speed.#1.........: 10337.1 MH/s (58.10ms) @ Accel:512 Loops:512 Thr:64 Vec:1

Hashmode: 4800 - iSCSI CHAP authentication, MD5(CHAP)

Speed.#1.........: 34009.7 MH/s (70.80ms) @ Accel:1024 Loops:1024 Thr:64 Vec:1

Hashmode: 4900 - sha1($salt.$pass.$salt)

Speed.#1.........: 15709.4 MH/s (76.69ms) @ Accel:1024 Loops:512 Thr:64 Vec:1

Hashmode: 5100 - Half MD5

Speed.#1.........: 31591.9 MH/s (76.25ms) @ Accel:1024 Loops:1024 Thr:64 Vec:1

Hashmode: 5200 - Password Safe v3 (Iterations: 2049)

Speed.#1.........:  3486.9 kH/s (55.60ms) @ Accel:256 Loops:1024 Thr:64 Vec:1

Hashmode: 5300 - IKE-PSK MD5

Speed.#1.........:  1908.1 MH/s (78.87ms) @ Accel:512 Loops:128 Thr:64 Vec:1

Hashmode: 5400 - IKE-PSK SHA1

Speed.#1.........:  1044.0 MH/s (72.09ms) @ Accel:256 Loops:128 Thr:64 Vec:1

Hashmode: 5500 - NetNTLMv1 / NetNTLMv1+ESS

Speed.#1.........: 56895.2 MH/s (42.26ms) @ Accel:1024 Loops:1024 Thr:64 Vec:1

Hashmode: 5600 - NetNTLMv2

Speed.#1.........:  3477.3 MH/s (86.41ms) @ Accel:512 Loops:256 Thr:64 Vec:1

Hashmode: 5700 - Cisco-IOS type 4 (SHA256)

Speed.#1.........:  8660.4 MH/s (69.44ms) @ Accel:256 Loops:1024 Thr:64 Vec:1

Hashmode: 5800 - Samsung Android Password/PIN (Iterations: 1023)

Speed.#1.........: 14588.6 kH/s (77.79ms) @ Accel:512 Loops:1023 Thr:64 Vec:1

Hashmode: 6000 - RIPEMD-160

Speed.#1.........: 10981.6 MH/s (54.80ms) @ Accel:256 Loops:1024 Thr:64 Vec:1

Hashmode: 6100 - Whirlpool

Speed.#1.........:  1125.0 MH/s (66.91ms) @ Accel:128 Loops:256 Thr:64 Vec:1

Hashmode: 6211 - TrueCrypt RIPEMD160 + XTS 512 bit (Iterations: 1999)

Speed.#1.........:   655.1 kH/s (55.57ms) @ Accel:256 Loops:128 Thr:64 Vec:1

Hashmode: 6212 - TrueCrypt RIPEMD160 + XTS 1024 bit (Iterations: 1999)

Speed.#1.........:   367.8 kH/s (49.02ms) @ Accel:128 Loops:128 Thr:64 Vec:1

Hashmode: 6213 - TrueCrypt RIPEMD160 + XTS 1536 bit (Iterations: 1999)

Speed.#1.........:   257.5 kH/s (69.91ms) @ Accel:128 Loops:128 Thr:64 Vec:1

Hashmode: 6221 - TrueCrypt SHA512 + XTS 512 bit (Iterations: 999)

Speed.#1.........:  1009.3 kH/s (63.61ms) @ Accel:256 Loops:124 Thr:64 Vec:1

Hashmode: 6222 - TrueCrypt SHA512 + XTS 1024 bit (Iterations: 999)

Speed.#1.........:   504.3 kH/s (63.72ms) @ Accel:128 Loops:124 Thr:64 Vec:1

Hashmode: 6223 - TrueCrypt SHA512 + XTS 1536 bit (Iterations: 999)

Speed.#1.........:   333.9 kH/s (50.61ms) @ Accel:128 Loops:62 Thr:64 Vec:1

Hashmode: 6231 - TrueCrypt Whirlpool + XTS 512 bit (Iterations: 999)

Speed.#1.........:   116.8 kH/s (69.33ms) @ Accel:32 Loops:124 Thr:64 Vec:1

Hashmode: 6232 - TrueCrypt Whirlpool + XTS 1024 bit (Iterations: 999)

Speed.#1.........:    60144 H/s (67.36ms) @ Accel:16 Loops:124 Thr:64 Vec:1

Hashmode: 6233 - TrueCrypt Whirlpool + XTS 1536 bit (Iterations: 999)

Speed.#1.........:    39649 H/s (108.49ms) @ Accel:32 Loops:62 Thr:64 Vec:1

Hashmode: 6241 - TrueCrypt RIPEMD160 + XTS 512 bit + boot-mode (Iterations: 999)

Speed.#1.........:  1295.1 kH/s (44.22ms) @ Accel:128 Loops:249 Thr:64 Vec:1

Hashmode: 6242 - TrueCrypt RIPEMD160 + XTS 1024 bit + boot-mode (Iterations: 999)

Speed.#1.........:   729.4 kH/s (65.00ms) @ Accel:64 Loops:499 Thr:64 Vec:1

Hashmode: 6243 - TrueCrypt RIPEMD160 + XTS 1536 bit + boot-mode (Iterations: 999)

Speed.#1.........:   511.0 kH/s (61.61ms) @ Accel:128 Loops:124 Thr:64 Vec:1

Hashmode: 6300 - AIX {smd5} (Iterations: 1000)

Speed.#1.........: 21438.8 kH/s (51.86ms) @ Accel:1024 Loops:500 Thr:64 Vec:1

Hashmode: 6400 - AIX {ssha256} (Iterations: 63)

Speed.#1.........: 47573.2 kH/s (41.24ms) @ Accel:1024 Loops:63 Thr:64 Vec:1

Hashmode: 6500 - AIX {ssha512} (Iterations: 63)

Speed.#1.........: 14978.6 kH/s (71.69ms) @ Accel:512 Loops:63 Thr:64 Vec:1

Hashmode: 6600 - 1Password, agilekeychain (Iterations: 999)

Speed.#1.........:  8377.2 kH/s (45.19ms) @ Accel:512 Loops:499 Thr:64 Vec:1

Hashmode: 6700 - AIX {ssha1} (Iterations: 63)

Speed.#1.........: 98866.1 kH/s (15.89ms) @ Accel:1024 Loops:63 Thr:64 Vec:1

Hashmode: 6800 - LastPass + LastPass sniffed (Iterations: 499)

Speed.#1.........:  6994.8 kH/s (80.62ms) @ Accel:256 Loops:499 Thr:64 Vec:1

Hashmode: 6900 - GOST R 34.11-94

Speed.#1.........:   622.8 MH/s (59.91ms) @ Accel:64 Loops:256 Thr:64 Vec:1

Hashmode: 7000 - FortiGate (FortiOS)

Speed.#1.........: 18504.4 MH/s (64.56ms) @ Accel:512 Loops:1024 Thr:64 Vec:1

Hashmode: 7100 - macOS v10.8+ (PBKDF2-SHA512) (Iterations: 1023)

Speed.#1.........:   991.3 kH/s (73.08ms) @ Accel:32 Loops:1023 Thr:64 Vec:1

Hashmode: 7200 - GRUB 2 (Iterations: 1023)

Speed.#1.........:   998.1 kH/s (65.09ms) @ Accel:256 Loops:127 Thr:64 Vec:1

Hashmode: 7300 - IPMI2 RAKP HMAC-SHA1

Speed.#1.........:  2660.0 MH/s (56.05ms) @ Accel:256 Loops:256 Thr:64 Vec:1

Hashmode: 7400 - sha256crypt $5$, SHA256 (Unix) (Iterations: 5000)

Speed.#1.........:   818.4 kH/s (70.77ms) @ Accel:256 Loops:512 Thr:64 Vec:1

Hashmode: 7401 - MySQL $A$ (sha256crypt) (Iterations: 5000)

Speed.#1.........:   776.1 kH/s (74.88ms) @ Accel:512 Loops:256 Thr:64 Vec:1

Hashmode: 7500 - Kerberos 5, etype 23, AS-REQ Pre-Auth

Speed.#1.........:   848.7 MH/s (88.32ms) @ Accel:256 Loops:128 Thr:64 Vec:1

Hashmode: 7700 - SAP CODVN B (BCODE)

Speed.#1.........:  2319.9 MH/s (64.47ms) @ Accel:512 Loops:128 Thr:64 Vec:1

Hashmode: 7701 - SAP CODVN B (BCODE) from RFC_READ_TABLE

Speed.#1.........:  2325.0 MH/s (64.23ms) @ Accel:512 Loops:128 Thr:64 Vec:1

Hashmode: 7800 - SAP CODVN F/G (PASSCODE)

Speed.#1.........:  2091.7 MH/s (71.52ms) @ Accel:512 Loops:128 Thr:64 Vec:1

Hashmode: 7801 - SAP CODVN F/G (PASSCODE) from RFC_READ_TABLE

Speed.#1.........:  2090.2 MH/s (71.50ms) @ Accel:512 Loops:128 Thr:64 Vec:1

Hashmode: 7900 - Drupal7 (Iterations: 16384)

Speed.#1.........:   118.1 kH/s (77.48ms) @ Accel:128 Loops:512 Thr:64 Vec:1

Hashmode: 8000 - Sybase ASE

Speed.#1.........:  1057.2 MH/s (70.70ms) @ Accel:256 Loops:128 Thr:64 Vec:1

Hashmode: 8100 - Citrix NetScaler (SHA1)

Speed.#1.........: 18005.0 MH/s (66.36ms) @ Accel:512 Loops:1024 Thr:64 Vec:1

Hashmode: 8200 - 1Password, cloudkeychain (Iterations: 39999)

Speed.#1.........:    25529 H/s (73.60ms) @ Accel:128 Loops:256 Thr:64 Vec:1

Hashmode: 8300 - DNSSEC (NSEC3)

Speed.#1.........:  7924.1 MH/s (75.54ms) @ Accel:256 Loops:1024 Thr:64 Vec:1

Hashmode: 8400 - WBB3 (Woltlab Burning Board)

Speed.#1.........:  3451.8 MH/s (86.75ms) @ Accel:512 Loops:256 Thr:64 Vec:1

Hashmode: 8500 - RACF

Speed.#1.........:  6841.5 MH/s (87.61ms) @ Accel:256 Loops:1024 Thr:64 Vec:1

Hashmode: 8600 - Lotus Notes/Domino 5

Speed.#1.........:   522.7 MH/s (71.52ms) @ Accel:128 Loops:128 Thr:64 Vec:1

Hashmode: 8700 - Lotus Notes/Domino 6

Speed.#1.........:   165.1 MH/s (56.46ms) @ Accel:16 Loops:256 Thr:64 Vec:1

Hashmode: 8800 - Android FDE <= 4.3 (Iterations: 1999)

Speed.#1.........:  2131.1 kH/s (68.06ms) @ Accel:256 Loops:512 Thr:64 Vec:1

Hashmode: 8900 - scrypt (Iterations: 16384)

Speed.#1.........:     2447 H/s (45.73ms) @ Accel:36 Loops:1024 Thr:64 Vec:1

Hashmode: 9000 - Password Safe v2 (Iterations: 1000)

Speed.#1.........:  1247.0 kH/s (37.08ms) @ Accel:128 Loops:1000 Thr:16 Vec:1

Hashmode: 9100 - Lotus Notes/Domino 8 (Iterations: 4999)

Speed.#1.........:  1704.4 kH/s (67.92ms) @ Accel:256 Loops:1024 Thr:64 Vec:1

Hashmode: 9200 - Cisco-IOS $8$ (PBKDF2-SHA256) (Iterations: 19999)

Speed.#1.........:   171.7 kH/s (85.48ms) @ Accel:128 Loops:1024 Thr:64 Vec:1

Hashmode: 9300 - Cisco-IOS $9$ (scrypt) (Iterations: 16384)

Speed.#1.........:    21679 H/s (1.09ms) @ Accel:36 Loops:1024 Thr:64 Vec:1

Hashmode: 9400 - MS Office 2007 (Iterations: 50000)

Speed.#1.........:   343.1 kH/s (70.00ms) @ Accel:1024 Loops:512 Thr:64 Vec:1

Hashmode: 9500 - MS Office 2010 (Iterations: 100000)

Speed.#1.........:   171.3 kH/s (70.13ms) @ Accel:1024 Loops:512 Thr:64 Vec:1

Hashmode: 9600 - MS Office 2013 (Iterations: 100000)

Speed.#1.........:    21183 H/s (70.98ms) @ Accel:512 Loops:128 Thr:64 Vec:1

Hashmode: 9700 - MS Office <= 2003 $0/$1, MD5 + RC4

Speed.#1.........:   765.9 MH/s (48.58ms) @ Accel:256 Loops:64 Thr:64 Vec:1

Hashmode: 9710 - MS Office <= 2003 $0/$1, MD5 + RC4, collider #1

Speed.#1.........:   926.0 MH/s (80.90ms) @ Accel:256 Loops:128 Thr:64 Vec:1

Hashmode: 9720 - MS Office <= 2003 $0/$1, MD5 + RC4, collider #2

Speed.#1.........:  3916.6 MH/s (76.32ms) @ Accel:512 Loops:256 Thr:64 Vec:1

Hashmode: 9800 - MS Office <= 2003 $3/$4, SHA1 + RC4

Speed.#1.........:   905.7 MH/s (82.66ms) @ Accel:256 Loops:128 Thr:64 Vec:1

Hashmode: 9810 - MS Office <= 2003 $3, SHA1 + RC4, collider #1

Speed.#1.........:   963.0 MH/s (77.67ms) @ Accel:256 Loops:128 Thr:64 Vec:1

Hashmode: 9820 - MS Office <= 2003 $3, SHA1 + RC4, collider #2

Speed.#1.........:  7989.8 MH/s (74.96ms) @ Accel:512 Loops:512 Thr:64 Vec:1

Hashmode: 9900 - Radmin2

Speed.#1.........: 16925.9 MH/s (70.76ms) @ Accel:1024 Loops:512 Thr:64 Vec:1

Hashmode: 10000 - Django (PBKDF2-SHA256) (Iterations: 9999)

Speed.#1.........:   343.2 kH/s (85.67ms) @ Accel:256 Loops:512 Thr:64 Vec:1

Hashmode: 10100 - SipHash

Speed.#1.........: 69043.0 MH/s (34.33ms) @ Accel:1024 Loops:1024 Thr:64 Vec:1

Hashmode: 10200 - CRAM-MD5

Speed.#1.........:  8024.3 MH/s (74.59ms) @ Accel:1024 Loops:256 Thr:64 Vec:1

Hashmode: 10300 - SAP CODVN H (PWDSALTEDHASH) iSSHA-1 (Iterations: 1023)

Speed.#1.........: 13648.8 kH/s (55.41ms) @ Accel:1024 Loops:511 Thr:64 Vec:1

Hashmode: 10400 - PDF 1.1 - 1.3 (Acrobat 2 - 4)

Speed.#1.........:   985.1 MH/s (76.03ms) @ Accel:256 Loops:128 Thr:64 Vec:1

Hashmode: 10410 - PDF 1.1 - 1.3 (Acrobat 2 - 4), collider #1

Speed.#1.........:  1045.8 MH/s (71.55ms) @ Accel:256 Loops:128 Thr:64 Vec:1

Hashmode: 10420 - PDF 1.1 - 1.3 (Acrobat 2 - 4), collider #2

Speed.#1.........: 16384.9 MH/s (73.06ms) @ Accel:1024 Loops:512 Thr:64 Vec:1

Hashmode: 10500 - PDF 1.4 - 1.6 (Acrobat 5 - 8) (Iterations: 70)

Speed.#1.........: 43828.6 kH/s (47.66ms) @ Accel:1024 Loops:70 Thr:64 Vec:1

Hashmode: 10600 - PDF 1.7 Level 3 (Acrobat 9)

Speed.#1.........:  8655.4 MH/s (69.11ms) @ Accel:512 Loops:512 Thr:64 Vec:1

Hashmode: 10700 - PDF 1.7 Level 8 (Acrobat 10 - 11) (Iterations: 64)

Speed.#1.........:   132.7 kH/s (103.74ms) @ Accel:96 Loops:4 Thr:64 Vec:1

Hashmode: 10800 - SHA2-384

Speed.#1.........:  2285.2 MH/s (65.37ms) @ Accel:128 Loops:512 Thr:64 Vec:1

Hashmode: 10900 - PBKDF2-HMAC-SHA256 (Iterations: 999)

Speed.#1.........:  3386.9 kH/s (56.95ms) @ Accel:256 Loops:499 Thr:64 Vec:1

Hashmode: 10901 - RedHat 389-DS LDAP (PBKDF2-HMAC-SHA256) (Iterations: 8191)

Speed.#1.........:   417.2 kH/s (87.96ms) @ Accel:128 Loops:1024 Thr:64 Vec:1

Hashmode: 11000 - PrestaShop

Speed.#1.........: 17836.6 MH/s (66.99ms) @ Accel:1024 Loops:512 Thr:64 Vec:1

Hashmode: 11100 - PostgreSQL CRAM (MD5)

Speed.#1.........: 15394.1 MH/s (77.83ms) @ Accel:1024 Loops:512 Thr:64 Vec:1

Hashmode: 11200 - MySQL CRAM (SHA1)

Speed.#1.........:  5645.3 MH/s (52.85ms) @ Accel:256 Loops:512 Thr:64 Vec:1

Hashmode: 11300 - Bitcoin/Litecoin wallet.dat (Iterations: 200459)

Speed.#1.........:    10689 H/s (70.27ms) @ Accel:128 Loops:512 Thr:64 Vec:1

Hashmode: 11400 - SIP digest authentication (MD5)

Speed.#1.........:  2504.7 MH/s (59.56ms) @ Accel:512 Loops:128 Thr:64 Vec:1

Hashmode: 11500 - CRC32

Speed.#1.........:   119.2 GH/s (19.61ms) @ Accel:1024 Loops:1024 Thr:64 Vec:1

Hashmode: 11600 - 7-Zip (Iterations: 16384)

Speed.#1.........:  1078.1 kH/s (64.34ms) @ Accel:128 Loops:4096 Thr:64 Vec:1

Hashmode: 11700 - GOST R 34.11-2012 (Streebog) 256-bit, big-endian

Speed.#1.........:   127.2 MH/s (73.49ms) @ Accel:32 Loops:128 Thr:64 Vec:1

Hashmode: 11750 - HMAC-Streebog-256 (key = $pass), big-endian

Speed.#1.........: 41208.2 kH/s (85.28ms) @ Accel:48 Loops:32 Thr:64 Vec:1

Hashmode: 11760 - HMAC-Streebog-256 (key = $salt), big-endian

Speed.#1.........: 54533.7 kH/s (85.90ms) @ Accel:8 Loops:256 Thr:64 Vec:1

Hashmode: 11800 - GOST R 34.11-2012 (Streebog) 512-bit, big-endian

Speed.#1.........:   120.0 MH/s (78.03ms) @ Accel:16 Loops:256 Thr:64 Vec:1

Hashmode: 11850 - HMAC-Streebog-512 (key = $pass), big-endian

Speed.#1.........: 35760.8 kH/s (81.78ms) @ Accel:40 Loops:32 Thr:64 Vec:1

Hashmode: 11860 - HMAC-Streebog-512 (key = $salt), big-endian

Speed.#1.........: 45539.5 kH/s (51.17ms) @ Accel:8 Loops:128 Thr:64 Vec:1

Hashmode: 11900 - PBKDF2-HMAC-MD5 (Iterations: 999)

Speed.#1.........: 14868.5 kH/s (49.88ms) @ Accel:1024 Loops:499 Thr:64 Vec:1

Hashmode: 12000 - PBKDF2-HMAC-SHA1 (Iterations: 999)

Speed.#1.........:  8282.9 kH/s (45.49ms) @ Accel:512 Loops:499 Thr:64 Vec:1

Hashmode: 12001 - Atlassian (PBKDF2-HMAC-SHA1) (Iterations: 9999)

Speed.#1.........:   858.7 kH/s (68.20ms) @ Accel:256 Loops:1024 Thr:64 Vec:1

Hashmode: 12100 - PBKDF2-HMAC-SHA512 (Iterations: 999)

Speed.#1.........:  1024.6 kH/s (63.42ms) @ Accel:256 Loops:124 Thr:64 Vec:1

Hashmode: 12200 - eCryptfs (Iterations: 65536)

Speed.#1.........:    32654 H/s (70.28ms) @ Accel:64 Loops:1024 Thr:64 Vec:1

Hashmode: 12300 - Oracle T: Type (Oracle 12+) (Iterations: 4095)

Speed.#1.........:   249.2 kH/s (73.40ms) @ Accel:32 Loops:1024 Thr:64 Vec:1

Hashmode: 12400 - BSDi Crypt, Extended DES (Iterations: 2194)

Speed.#1.........:  5055.5 kH/s (91.63ms) @ Accel:1024 Loops:512 Thr:64 Vec:1

Hashmode: 12500 - RAR3-hp (Iterations: 262144)

Speed.#1.........:   137.7 kH/s (66.38ms) @ Accel:64 Loops:16384 Thr:64 Vec:1

Hashmode: 12600 - ColdFusion 10+

Speed.#1.........:  5083.1 MH/s (58.73ms) @ Accel:128 Loops:1024 Thr:64 Vec:1

Hashmode: 12700 - Blockchain, My Wallet (Iterations: 9)

Speed.#1.........:   162.7 MH/s (4.58ms) @ Accel:1024 Loops:9 Thr:64 Vec:1

Hashmode: 12800 - MS-AzureSync PBKDF2-HMAC-SHA256 (Iterations: 99)

Speed.#1.........: 31116.2 kH/s (63.64ms) @ Accel:1024 Loops:99 Thr:64 Vec:1

Hashmode: 12900 - Android FDE (Samsung DEK) (Iterations: 4095)

Speed.#1.........:   875.5 kH/s (83.45ms) @ Accel:256 Loops:512 Thr:64 Vec:1

Hashmode: 13000 - RAR5 (Iterations: 32799)

Speed.#1.........:   109.7 kH/s (83.68ms) @ Accel:256 Loops:512 Thr:64 Vec:1

Hashmode: 13100 - Kerberos 5, etype 23, TGS-REP

Speed.#1.........:   814.1 MH/s (92.08ms) @ Accel:512 Loops:64 Thr:64 Vec:1

Hashmode: 13200 - AxCrypt 1 (Iterations: 10467)

Speed.#1.........:   297.1 kH/s (180.04ms) @ Accel:256 Loops:1024 Thr:64 Vec:1

Hashmode: 13300 - AxCrypt 1 in-memory SHA1

Speed.#1.........: 19172.3 MH/s (62.31ms) @ Accel:512 Loops:1024 Thr:64 Vec:1

Hashmode: 13400 - KeePass 1 (AES/Twofish) and KeePass 2 (AES) (Iterations: 24569)

Speed.#1.........:    86471 H/s (283.82ms) @ Accel:512 Loops:512 Thr:64 Vec:1

Hashmode: 13500 - PeopleSoft PS_TOKEN

Speed.#1.........: 14792.2 MH/s (81.02ms) @ Accel:512 Loops:1024 Thr:64 Vec:1

Hashmode: 13600 - WinZip (Iterations: 999)

Speed.#1.........:  8178.6 kH/s (68.13ms) @ Accel:256 Loops:999 Thr:64 Vec:1

Hashmode: 13711 - VeraCrypt RIPEMD160 + XTS 512 bit (Iterations: 655330)

Speed.#1.........:     1992 H/s (27.97ms) @ Accel:256 Loops:125 Thr:64 Vec:1

Hashmode: 13712 - VeraCrypt RIPEMD160 + XTS 1024 bit (Iterations: 655330)

Speed.#1.........:     1146 H/s (48.73ms) @ Accel:256 Loops:125 Thr:64 Vec:1

Hashmode: 13713 - VeraCrypt RIPEMD160 + XTS 1536 bit (Iterations: 655330)

Speed.#1.........:      802 H/s (34.75ms) @ Accel:128 Loops:125 Thr:64 Vec:1

Hashmode: 13721 - VeraCrypt SHA512 + XTS 512 bit (Iterations: 499999)

Speed.#1.........:     2042 H/s (35.79ms) @ Accel:128 Loops:250 Thr:64 Vec:1

Hashmode: 13722 - VeraCrypt SHA512 + XTS 1024 bit (Iterations: 499999)

Speed.#1.........:     1023 H/s (35.74ms) @ Accel:64 Loops:250 Thr:64 Vec:1

Hashmode: 13723 - VeraCrypt SHA512 + XTS 1536 bit (Iterations: 499999)

Speed.#1.........:      681 H/s (26.59ms) @ Accel:128 Loops:62 Thr:64 Vec:1

Hashmode: 13731 - VeraCrypt Whirlpool + XTS 512 bit (Iterations: 499999)

Speed.#1.........:      238 H/s (38.40ms) @ Accel:8 Loops:500 Thr:64 Vec:1

Hashmode: 13732 - VeraCrypt Whirlpool + XTS 1024 bit (Iterations: 499999)

Speed.#1.........:      119 H/s (38.43ms) @ Accel:8 Loops:250 Thr:64 Vec:1

Hashmode: 13733 - VeraCrypt Whirlpool + XTS 1536 bit (Iterations: 499999)

Speed.#1.........:       78 H/s (58.21ms) @ Accel:32 Loops:62 Thr:64 Vec:1

Hashmode: 13741 - VeraCrypt RIPEMD160 + XTS 512 bit + boot-mode (Iterations: 327660)

Speed.#1.........:     4000 H/s (28.51ms) @ Accel:64 Loops:512 Thr:64 Vec:1

Hashmode: 13742 - VeraCrypt RIPEMD160 + XTS 1024 bit + boot-mode (Iterations: 327660)

Speed.#1.........:     2298 H/s (24.82ms) @ Accel:128 Loops:128 Thr:64 Vec:1

Hashmode: 13743 - VeraCrypt RIPEMD160 + XTS 1536 bit + boot-mode (Iterations: 327660)

Speed.#1.........:     1612 H/s (35.44ms) @ Accel:128 Loops:128 Thr:64 Vec:1

Hashmode: 13751 - VeraCrypt SHA256 + XTS 512 bit (Iterations: 499999)

Speed.#1.........:     3437 H/s (42.59ms) @ Accel:128 Loops:500 Thr:64 Vec:1

Hashmode: 13752 - VeraCrypt SHA256 + XTS 1024 bit (Iterations: 499999)

Speed.#1.........:     1721 H/s (42.60ms) @ Accel:128 Loops:250 Thr:64 Vec:1

Hashmode: 13753 - VeraCrypt SHA256 + XTS 1536 bit (Iterations: 499999)

Speed.#1.........:     1140 H/s (32.05ms) @ Accel:32 Loops:500 Thr:64 Vec:1

Hashmode: 13761 - VeraCrypt SHA256 + XTS 512 bit + boot-mode (Iterations: 199999)

Speed.#1.........:     8589 H/s (43.75ms) @ Accel:128 Loops:512 Thr:64 Vec:1

Hashmode: 13762 - VeraCrypt SHA256 + XTS 1024 bit + boot-mode (Iterations: 199999)

Speed.#1.........:     4302 H/s (43.65ms) @ Accel:128 Loops:256 Thr:64 Vec:1

Hashmode: 13763 - VeraCrypt SHA256 + XTS 1536 bit + boot-mode (Iterations: 199999)

Speed.#1.........:     2813 H/s (33.29ms) @ Accel:16 Loops:1024 Thr:64 Vec:1

Hashmode: 13771 - VeraCrypt Streebog-512 + XTS 512 bit (Iterations: 499999)

Speed.#1.........:       76 H/s (59.97ms) @ Accel:32 Loops:62 Thr:64 Vec:1

Hashmode: 13772 - VeraCrypt Streebog-512 + XTS 1024 bit (Iterations: 499999)

Speed.#1.........:       40 H/s (76.69ms) @ Accel:192 Loops:7 Thr:64 Vec:1

Hashmode: 13773 - VeraCrypt Streebog-512 + XTS 1536 bit (Iterations: 499999)

Speed.#1.........:       24 H/s (46.42ms) @ Accel:8 Loops:62 Thr:64 Vec:1

Hashmode: 13800 - Windows Phone 8+ PIN/password

Speed.#1.........:  2231.8 MH/s (66.94ms) @ Accel:512 Loops:128 Thr:64 Vec:1

Hashmode: 13900 - OpenCart

Speed.#1.........:  5453.2 MH/s (54.70ms) @ Accel:256 Loops:512 Thr:64 Vec:1

Hashmode: 14000 - DES (PT = $salt, key = $pass)

Speed.#1.........: 51170.5 MH/s (46.38ms) @ Accel:1024 Loops:1024 Thr:64 Vec:1

Hashmode: 14100 - 3DES (PT = $salt, key = $pass)

Speed.#1.........:  7089.7 MH/s (84.50ms) @ Accel:256 Loops:1024 Thr:64 Vec:1

Hashmode: 14400 - sha1(CX)

Speed.#1.........:   997.9 MH/s (75.01ms) @ Accel:256 Loops:128 Thr:64 Vec:1

Hashmode: 14600 - LUKS (Iterations: 163044)

Speed.#1.........:    26530 H/s (69.65ms) @ Accel:256 Loops:512 Thr:64 Vec:1

Hashmode: 14700 - iTunes backup < 10.0 (Iterations: 9999)

Speed.#1.........:   430.6 kH/s (68.00ms) @ Accel:256 Loops:512 Thr:64 Vec:1

Hashmode: 14800 - iTunes backup >= 10.0 (Iterations: 9999999)

Speed.#1.........:      346 H/s (87.17ms) @ Accel:256 Loops:512 Thr:64 Vec:1

Hashmode: 14900 - Skip32 (PT = $salt, key = $pass)

Speed.#1.........: 12013.9 MH/s (2.33ms) @ Accel:1024 Loops:512 Thr:64 Vec:1

Hashmode: 15000 - FileZilla Server >= 0.9.55

Speed.#1.........:  2327.3 MH/s (64.25ms) @ Accel:128 Loops:512 Thr:64 Vec:1

Hashmode: 15100 - Juniper/NetBSD sha1crypt (Iterations: 19999)

Speed.#1.........:   432.4 kH/s (67.81ms) @ Accel:256 Loops:1024 Thr:64 Vec:1

Hashmode: 15200 - Blockchain, My Wallet, V2 (Iterations: 4999)

Speed.#1.........:   862.9 kH/s (67.91ms) @ Accel:512 Loops:256 Thr:64 Vec:1

Hashmode: 15300 - DPAPI masterkey file v1 (Iterations: 23999)

Speed.#1.........:   179.3 kH/s (68.12ms) @ Accel:128 Loops:1024 Thr:64 Vec:1

Hashmode: 15400 - ChaCha20

Speed.#1.........: 10228.6 MH/s (235.50ms) @ Accel:1024 Loops:1024 Thr:64 Vec:1

Hashmode: 15500 - JKS Java Key Store Private Keys (SHA1)

Speed.#1.........: 19728.5 MH/s (60.53ms) @ Accel:1024 Loops:512 Thr:64 Vec:1

Hashmode: 15600 - Ethereum Wallet, PBKDF2-HMAC-SHA256 (Iterations: 1023)

Speed.#1.........:  3482.5 kH/s (66.35ms) @ Accel:512 Loops:255 Thr:64 Vec:1

Hashmode: 15700 - Ethereum Wallet, SCRYPT (Iterations: 262144)

Speed.#1.........:        1 H/s (9.00ms) @ Accel:1 Loops:1024 Thr:4 Vec:1

Hashmode: 15900 - DPAPI masterkey file v2 (Iterations: 12899)

Speed.#1.........:    80094 H/s (70.56ms) @ Accel:32 Loops:1024 Thr:64 Vec:1

Hashmode: 16000 - Tripcode

Speed.#1.........:   451.4 MH/s (82.93ms) @ Accel:256 Loops:64 Thr:64 Vec:1

Hashmode: 16100 - TACACS+

Speed.#1.........: 31422.4 MH/s (76.25ms) @ Accel:1024 Loops:1024 Thr:64 Vec:1

Hashmode: 16200 - Apple Secure Notes (Iterations: 19999)

Speed.#1.........:   181.1 kH/s (81.18ms) @ Accel:256 Loops:512 Thr:64 Vec:1

Hashmode: 16300 - Ethereum Pre-Sale Wallet, PBKDF2-HMAC-SHA256 (Iterations: 1999)

Speed.#1.........:  1774.1 kH/s (80.77ms) @ Accel:128 Loops:1024 Thr:64 Vec:1

Hashmode: 16400 - CRAM-MD5 Dovecot

Speed.#1.........: 51826.0 MH/s (45.99ms) @ Accel:1024 Loops:1024 Thr:64 Vec:1

Hashmode: 16500 - JWT (JSON Web Token)

Speed.#1.........:  1686.9 MH/s (88.85ms) @ Accel:256 Loops:256 Thr:64 Vec:1

Hashmode: 16600 - Electrum Wallet (Salt-Type 1-3)

Speed.#1.........:  1345.6 MH/s (55.38ms) @ Accel:32 Loops:1024 Thr:64 Vec:1

Hashmode: 16700 - FileVault 2 (Iterations: 19999)

Speed.#1.........:   181.0 kH/s (81.22ms) @ Accel:256 Loops:512 Thr:64 Vec:1

Hashmode: 16800 - WPA-PMKID-PBKDF2 (Iterations: 4095)

Speed.#1.........:  1048.3 kH/s (69.86ms) @ Accel:256 Loops:512 Thr:64 Vec:1

Hashmode: 16801 - WPA-PMKID-PMK (Iterations: 0)

Speed.#1.........:   397.9 MH/s (0.00ms) @ Accel:1024 Loops:1024 Thr:64 Vec:1

Hashmode: 16900 - Ansible Vault (Iterations: 9999)

Speed.#1.........:   361.4 kH/s (81.15ms) @ Accel:128 Loops:1024 Thr:64 Vec:1

Hashmode: 17200 - PKZIP (Compressed)

Speed.#1.........: 35338.1 kH/s (266.44ms) @ Accel:4 Loops:1024 Thr:64 Vec:1

Hashmode: 17210 - PKZIP (Uncompressed)

Speed.#1.........:  3555.6 MH/s (41.78ms) @ Accel:512 Loops:128 Thr:64 Vec:1

Hashmode: 17220 - PKZIP (Compressed Multi-File)

Speed.#1.........:   129.0 MH/s (72.53ms) @ Accel:8 Loops:512 Thr:64 Vec:1

Hashmode: 17225 - PKZIP (Mixed Multi-File)

Speed.#1.........:   157.1 MH/s (58.58ms) @ Accel:128 Loops:32 Thr:64 Vec:1

Hashmode: 17230 - PKZIP (Mixed Multi-File Checksum-Only)

Speed.#1.........: 23355.8 MH/s (50.93ms) @ Accel:1024 Loops:512 Thr:64 Vec:1

Hashmode: 17300 - SHA3-224

Speed.#1.........:  1413.2 MH/s (52.81ms) @ Accel:128 Loops:256 Thr:64 Vec:1

Hashmode: 17400 - SHA3-256

Speed.#1.........:  1408.0 MH/s (52.97ms) @ Accel:128 Loops:256 Thr:64 Vec:1

Hashmode: 17500 - SHA3-384

Speed.#1.........:  1406.9 MH/s (53.03ms) @ Accel:64 Loops:512 Thr:64 Vec:1

Hashmode: 17600 - SHA3-512

Speed.#1.........:  1407.2 MH/s (52.99ms) @ Accel:128 Loops:256 Thr:64 Vec:1

Hashmode: 17700 - Keccak-224

Speed.#1.........:  1403.0 MH/s (53.10ms) @ Accel:64 Loops:512 Thr:64 Vec:1

Hashmode: 17800 - Keccak-256

Speed.#1.........:  1400.9 MH/s (53.22ms) @ Accel:128 Loops:256 Thr:64 Vec:1

Hashmode: 17900 - Keccak-384

Speed.#1.........:  1406.7 MH/s (53.01ms) @ Accel:128 Loops:256 Thr:64 Vec:1

Hashmode: 18000 - Keccak-512

Speed.#1.........:  1404.3 MH/s (53.08ms) @ Accel:128 Loops:256 Thr:64 Vec:1

Hashmode: 18100 - TOTP (HMAC-SHA1)

Speed.#1.........:  4370.4 MH/s (68.33ms) @ Accel:512 Loops:256 Thr:64 Vec:1

Hashmode: 18200 - Kerberos 5, etype 23, AS-REP

Speed.#1.........:   818.9 MH/s (91.55ms) @ Accel:512 Loops:64 Thr:64 Vec:1

Hashmode: 18300 - Apple File System (APFS) (Iterations: 19999)

Speed.#1.........:   181.9 kH/s (80.77ms) @ Accel:256 Loops:512 Thr:64 Vec:1

Hashmode: 18400 - Open Document Format (ODF) 1.2 (SHA-256, AES) (Iterations: 99999)

Speed.#1.........:    43214 H/s (69.73ms) @ Accel:128 Loops:1024 Thr:64 Vec:1

Hashmode: 18500 - sha1(md5(md5($pass)))

Speed.#1.........:  7208.6 MH/s (83.03ms) @ Accel:512 Loops:512 Thr:64 Vec:1

Hashmode: 18600 - Open Document Format (ODF) 1.1 (SHA-1, Blowfish) (Iterations: 1023)

Speed.#1.........:  1883.2 kH/s (64.30ms) @ Accel:512 Loops:1023 Thr:16 Vec:1

Hashmode: 18700 - Java Object hashCode()

Speed.#1.........:   123.5 GH/s (18.85ms) @ Accel:1024 Loops:1024 Thr:64 Vec:1

Hashmode: 18800 - Blockchain, My Wallet, Second Password (SHA256) (Iterations: 9999)

Speed.#1.........:   728.0 kH/s (80.75ms) @ Accel:1024 Loops:256 Thr:64 Vec:1

Hashmode: 18900 - Android Backup (Iterations: 9999)

Speed.#1.........:   434.7 kH/s (67.62ms) @ Accel:256 Loops:512 Thr:64 Vec:1

Hashmode: 19000 - QNX /etc/shadow (MD5) (Iterations: 1000)

Speed.#1.........:  7624.3 kH/s (75.25ms) @ Accel:512 Loops:500 Thr:64 Vec:1

Hashmode: 19100 - QNX /etc/shadow (SHA256) (Iterations: 1000)

Speed.#1.........: 12026.0 kH/s (94.30ms) @ Accel:1024 Loops:500 Thr:64 Vec:1

Hashmode: 19200 - QNX /etc/shadow (SHA512) (Iterations: 1000)

Speed.#1.........:  7965.7 kH/s (70.36ms) @ Accel:256 Loops:1000 Thr:64 Vec:1

Hashmode: 19300 - sha1($salt1.$pass.$salt2)

Speed.#1.........:  1187.9 MH/s (62.89ms) @ Accel:32 Loops:1024 Thr:64 Vec:1

Hashmode: 19500 - Ruby on Rails Restful-Authentication

Speed.#1.........:   201.2 MH/s (93.14ms) @ Accel:8 Loops:1024 Thr:64 Vec:1

Hashmode: 19600 - Kerberos 5, etype 17, TGS-REP (Iterations: 4095)

Speed.#1.........:  2109.7 kH/s (69.01ms) @ Accel:512 Loops:512 Thr:64 Vec:1

Hashmode: 19700 - Kerberos 5, etype 18, TGS-REP (Iterations: 4095)

Speed.#1.........:  1058.6 kH/s (69.02ms) @ Accel:256 Loops:512 Thr:64 Vec:1

Hashmode: 19800 - Kerberos 5, etype 17, Pre-Auth (Iterations: 4095)

Speed.#1.........:  2114.0 kH/s (68.83ms) @ Accel:256 Loops:1024 Thr:64 Vec:1

Hashmode: 19900 - Kerberos 5, etype 18, Pre-Auth (Iterations: 4095)

Speed.#1.........:  1058.9 kH/s (69.06ms) @ Accel:256 Loops:512 Thr:64 Vec:1

Hashmode: 20011 - DiskCryptor SHA512 + XTS 512 bit (Iterations: 999)

Speed.#1.........:  1026.5 kH/s (62.75ms) @ Accel:256 Loops:124 Thr:64 Vec:1

Hashmode: 20012 - DiskCryptor SHA512 + XTS 1024 bit (Iterations: 999)

Speed.#1.........:   512.1 kH/s (62.77ms) @ Accel:128 Loops:124 Thr:64 Vec:1

Hashmode: 20013 - DiskCryptor SHA512 + XTS 1536 bit (Iterations: 999)

Speed.#1.........:   340.2 kH/s (49.91ms) @ Accel:128 Loops:62 Thr:64 Vec:1

Hashmode: 20200 - Python passlib pbkdf2-sha512 (Iterations: 24999)

Speed.#1.........:    41443 H/s (72.66ms) @ Accel:128 Loops:256 Thr:64 Vec:1

Hashmode: 20300 - Python passlib pbkdf2-sha256 (Iterations: 28999)

Speed.#1.........:   119.4 kH/s (86.90ms) @ Accel:256 Loops:512 Thr:64 Vec:1

Hashmode: 20400 - Python passlib pbkdf2-sha1 (Iterations: 130999)

Speed.#1.........:    65959 H/s (69.53ms) @ Accel:256 Loops:1024 Thr:64 Vec:1

Hashmode: 20500 - PKZIP Master Key

Speed.#1.........:   200.0 GH/s (11.47ms) @ Accel:1024 Loops:1024 Thr:64 Vec:1

Hashmode: 20510 - PKZIP Master Key (6 byte optimization)

Speed.#1.........: 34277.6 MH/s (69.82ms) @ Accel:1024 Loops:1024 Thr:64 Vec:1

Hashmode: 20600 - Oracle Transportation Management (SHA256) (Iterations: 999)

Speed.#1.........:  7180.0 kH/s (53.40ms) @ Accel:512 Loops:499 Thr:64 Vec:1

Hashmode: 20710 - sha256(sha256($pass).$salt)

Speed.#1.........:  2404.4 MH/s (62.17ms) @ Accel:256 Loops:256 Thr:64 Vec:1

Hashmode: 20711 - AuthMe sha256

Speed.#1.........:  2396.4 MH/s (62.28ms) @ Accel:512 Loops:128 Thr:64 Vec:1

Hashmode: 20800 - sha256(md5($pass))

Speed.#1.........:  6506.0 MH/s (92.19ms) @ Accel:512 Loops:512 Thr:64 Vec:1

Hashmode: 20900 - md5(sha1($pass).md5($pass).sha1($pass))

Speed.#1.........:  5777.6 MH/s (51.65ms) @ Accel:256 Loops:512 Thr:64 Vec:1

Hashmode: 21000 - BitShares v0.x - sha512(sha512_bin(pass))

Speed.#1.........:   888.9 MH/s (84.32ms) @ Accel:32 Loops:1024 Thr:64 Vec:1

Hashmode: 21100 - sha1(md5($pass.$salt))

Speed.#1.........: 10966.9 MH/s (54.43ms) @ Accel:512 Loops:512 Thr:64 Vec:1

Hashmode: 21200 - md5(sha1($salt).md5($pass))

Speed.#1.........: 10923.8 MH/s (54.56ms) @ Accel:1024 Loops:256 Thr:64 Vec:1

Hashmode: 21300 - md5($salt.sha1($salt.$pass))

Speed.#1.........:  7575.9 MH/s (78.99ms) @ Accel:512 Loops:512 Thr:64 Vec:1

Hashmode: 21400 - sha256(sha256_bin($pass))

Speed.#1.........:  3948.4 MH/s (75.85ms) @ Accel:256 Loops:512 Thr:64 Vec:1

Hashmode: 21500 - SolarWinds Orion (Iterations: 999)

Speed.#1.........:   163.5 kH/s (52.36ms) @ Accel:64 Loops:62 Thr:64 Vec:1

Hashmode: 21501 - SolarWinds Orion v2 (Iterations: 999)

Speed.#1.........:   163.5 kH/s (52.59ms) @ Accel:64 Loops:62 Thr:64 Vec:1

Hashmode: 21600 - Web2py pbkdf2-sha512 (Iterations: 999)

Speed.#1.........:  1034.7 kH/s (62.77ms) @ Accel:256 Loops:124 Thr:64 Vec:1

Hashmode: 21700 - Electrum Wallet (Salt-Type 4) (Iterations: 1023)

Speed.#1.........:   663.2 kH/s (64.25ms) @ Accel:256 Loops:127 Thr:64 Vec:1

Hashmode: 21800 - Electrum Wallet (Salt-Type 5) (Iterations: 1023)

Speed.#1.........:   663.3 kH/s (64.25ms) @ Accel:256 Loops:127 Thr:64 Vec:1

Hashmode: 22000 - WPA-PBKDF2-PMKID+EAPOL (Iterations: 4095)

Speed.#1.........:  1060.4 kH/s (69.15ms) @ Accel:256 Loops:512 Thr:64 Vec:1

Hashmode: 22001 - WPA-PMK-PMKID+EAPOL (Iterations: 0)

Speed.#1.........:   398.7 MH/s (0.00ms) @ Accel:1024 Loops:1024 Thr:64 Vec:1

Hashmode: 22100 - BitLocker (Iterations: 1048576)

Speed.#1.........:     3959 H/s (72.52ms) @ Accel:32 Loops:4096 Thr:64 Vec:1

Hashmode: 22200 - Citrix NetScaler (SHA512)

Speed.#1.........:  2310.9 MH/s (64.67ms) @ Accel:128 Loops:512 Thr:64 Vec:1

Hashmode: 22300 - sha256($salt.$pass.$salt)

Speed.#1.........:  7717.5 MH/s (77.60ms) @ Accel:512 Loops:512 Thr:64 Vec:1

Hashmode: 22301 - Telegram Mobile App Passcode (SHA256)

Speed.#1.........:  7714.3 MH/s (77.65ms) @ Accel:256 Loops:1024 Thr:64 Vec:1

Hashmode: 22400 - AES Crypt (SHA256) (Iterations: 8191)

Speed.#1.........:   803.4 kH/s (90.73ms) @ Accel:256 Loops:1024 Thr:64 Vec:1

Hashmode: 22500 - MultiBit Classic .key (MD5)

Speed.#1.........:  1376.6 MH/s (54.14ms) @ Accel:32 Loops:1024 Thr:64 Vec:1

Hashmode: 22600 - Telegram Desktop < v2.1.14 (PBKDF2-HMAC-SHA1) (Iterations: 3999)

Speed.#1.........:   309.2 kH/s (59.27ms) @ Accel:128 Loops:256 Thr:64 Vec:1

Hashmode: 22700 - MultiBit HD (scrypt) (Iterations: 16384)

Speed.#1.........:     2463 H/s (45.83ms) @ Accel:36 Loops:1024 Thr:64 Vec:1

Hashmode: 22911 - RSA/DSA/EC/OpenSSH Private Keys ($0$)

Speed.#1.........:  1163.2 MH/s (64.28ms) @ Accel:256 Loops:128 Thr:64 Vec:1

Hashmode: 22921 - RSA/DSA/EC/OpenSSH Private Keys ($6$)

Speed.#1.........:  5039.7 MH/s (59.29ms) @ Accel:512 Loops:256 Thr:64 Vec:1

Hashmode: 22931 - RSA/DSA/EC/OpenSSH Private Keys ($1, $3$)

Speed.#1.........:  1954.9 MH/s (76.57ms) @ Accel:512 Loops:128 Thr:64 Vec:1

Hashmode: 22941 - RSA/DSA/EC/OpenSSH Private Keys ($4$)

Speed.#1.........:  1645.2 MH/s (91.06ms) @ Accel:256 Loops:256 Thr:64 Vec:1

Hashmode: 22951 - RSA/DSA/EC/OpenSSH Private Keys ($5$)

Speed.#1.........:  1199.2 MH/s (62.27ms) @ Accel:256 Loops:128 Thr:64 Vec:1

Hashmode: 23001 - SecureZIP AES-128

Speed.#1.........:  2034.8 MH/s (73.57ms) @ Accel:256 Loops:256 Thr:64 Vec:1

Hashmode: 23002 - SecureZIP AES-192

Speed.#1.........:  1624.0 MH/s (92.32ms) @ Accel:64 Loops:1024 Thr:64 Vec:1

Hashmode: 23003 - SecureZIP AES-256

Speed.#1.........:  1186.1 MH/s (63.04ms) @ Accel:64 Loops:512 Thr:64 Vec:1

Hashmode: 23100 - Apple Keychain (Iterations: 999)

Speed.#1.........:  4288.4 kH/s (53.87ms) @ Accel:512 Loops:249 Thr:64 Vec:1

Hashmode: 23200 - XMPP SCRAM PBKDF2-SHA1 (Iterations: 4095)

Speed.#1.........:  2111.5 kH/s (69.02ms) @ Accel:256 Loops:1024 Thr:64 Vec:1

Hashmode: 23300 - Apple iWork (Iterations: 3999)

Speed.#1.........:  2159.8 kH/s (67.47ms) @ Accel:512 Loops:512 Thr:64 Vec:1

Hashmode: 23400 - Bitwarden (Iterations: 99999)

Speed.#1.........:    36486 H/s (82.52ms) @ Accel:256 Loops:512 Thr:64 Vec:1

Hashmode: 23500 - AxCrypt 2 AES-128 (Iterations: 999)

Speed.#1.........:   136.0 kH/s (47.94ms) @ Accel:256 Loops:124 Thr:64 Vec:1

Hashmode: 23600 - AxCrypt 2 AES-256 (Iterations: 999)

Speed.#1.........:    69451 H/s (94.22ms) @ Accel:256 Loops:124 Thr:64 Vec:1

Hashmode: 23700 - RAR3-p (Uncompressed) (Iterations: 262144)

Speed.#1.........:   139.4 kH/s (65.66ms) @ Accel:64 Loops:16384 Thr:64 Vec:1

Hashmode: 23800 - RAR3-p (Compressed) (Iterations: 262144)

Speed.#1.........:   135.5 kH/s (65.69ms) @ Accel:64 Loops:16384 Thr:64 Vec:1

Hashmode: 23900 - BestCrypt v3 Volume Encryption (Iterations: 1)

Speed.#1.........:  5909.9 kH/s (94.74ms) @ Accel:256 Loops:1 Thr:64 Vec:1

Hashmode: 24100 - MongoDB ServerKey SCRAM-SHA-1 (Iterations: 9999)

Speed.#1.........:   868.7 kH/s (67.50ms) @ Accel:512 Loops:512 Thr:64 Vec:1

Hashmode: 24200 - MongoDB ServerKey SCRAM-SHA-256 (Iterations: 14999)

Speed.#1.........:   243.2 kH/s (80.45ms) @ Accel:256 Loops:512 Thr:64 Vec:1

Hashmode: 24300 - sha1($salt.sha1($pass.$salt))

Speed.#1.........:  7812.5 MH/s (76.58ms) @ Accel:1024 Loops:256 Thr:64 Vec:1

Hashmode: 24410 - PKCS#8 Private Keys (PBKDF2-HMAC-SHA1 + 3DES/AES) (Iterations: 2047)

Speed.#1.........:  2107.5 kH/s (69.00ms) @ Accel:256 Loops:512 Thr:64 Vec:1

Hashmode: 24420 - PKCS#8 Private Keys (PBKDF2-HMAC-SHA256 + 3DES/AES) (Iterations: 2047)

Speed.#1.........:  1691.9 kH/s (86.20ms) @ Accel:256 Loops:512 Thr:64 Vec:1

Hashmode: 24500 - Telegram Desktop >= v2.1.14 (PBKDF2-HMAC-SHA512) (Iterations: 99999)

Speed.#1.........:     3452 H/s (54.44ms) @ Accel:128 Loops:64 Thr:64 Vec:1

Hashmode: 24600 - SQLCipher (Iterations: 63999)

Speed.#1.........:    67785 H/s (69.22ms) @ Accel:512 Loops:256 Thr:64 Vec:1

Hashmode: 24700 - Stuffit5

Speed.#1.........: 16948.3 MH/s (70.96ms) @ Accel:1024 Loops:512 Thr:64 Vec:1

Hashmode: 24800 - Umbraco HMAC-SHA1

Speed.#1.........:  4450.8 MH/s (67.54ms) @ Accel:256 Loops:512 Thr:64 Vec:1

Hashmode: 24900 - Dahua Authentication MD5

Speed.#1.........: 33396.9 MH/s (72.11ms) @ Accel:1024 Loops:1024 Thr:64 Vec:1

Hashmode: 25300 - MS Office 2016 - SheetProtection (Iterations: 100000)

Speed.#1.........:    21516 H/s (69.92ms) @ Accel:512 Loops:128 Thr:64 Vec:1

Hashmode: 25400 - PDF 1.4 - 1.6 (Acrobat 5 - 8) - edit password (Iterations: 70)

Speed.#1.........: 44116.7 kH/s (47.33ms) @ Accel:1024 Loops:70 Thr:64 Vec:1

Hashmode: 25500 - Stargazer Stellar Wallet XLM (Iterations: 4095)

Speed.#1.........:   890.9 kH/s (82.22ms) @ Accel:256 Loops:512 Thr:64 Vec:1

Hashmode: 25900 - KNX IP Secure - Device Authentication Code (Iterations: 65535)

Speed.#1.........:    55610 H/s (82.58ms) @ Accel:256 Loops:512 Thr:64 Vec:1

Hashmode: 26000 - Mozilla key3.db

Speed.#1.........:   565.6 MH/s (66.42ms) @ Accel:16 Loops:1024 Thr:64 Vec:1

Hashmode: 26100 - Mozilla key4.db (Iterations: 9999)

Speed.#1.........:   347.6 kH/s (84.57ms) @ Accel:512 Loops:256 Thr:64 Vec:1

Hashmode: 99999 - Plaintext

Speed.#1.........: 85655.2 MH/s (27.89ms) @ Accel:1024 Loops:1024 Thr:64 Vec:1

Started: Wed May  5 19:08:43 2021
Stopped: Wed May  5 20:04:18 2021
```
