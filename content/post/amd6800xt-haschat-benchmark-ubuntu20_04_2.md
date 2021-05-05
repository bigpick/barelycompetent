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


```bash
# still running
```
