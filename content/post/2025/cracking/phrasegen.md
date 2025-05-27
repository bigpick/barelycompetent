---
title: "Intoducing: phrasegen (v2!)"
date: 2025-05-27T00:00:00-00:01
url: "/phrasegen"
Description: |
    Announcing the re-release of phrasegen - now a pre-built and published
    Golang binary!
type: posts
sidebar_toc: true
categories:
 - cracking
tags:
 - golang
 - password-cracking
---

Generating sliding window ngrams of specified customizations over a given body of text.
Great for generating passphrase candidates with a focus on human memorization from a
given source material.

Check out the latest release of [phrasegen](https://github.com/ThatOnePasswordWas40Passwords/phrasegen)
for all your passphrase generating needs!

## Why

Q: Many other tools for building wordlists from input material already exist, why bother
with this?

A: Sometimes less is more. When you _only_ want generated passphrases that maintain
original apperance ordering, this is the tool you want. A massive keyspace generated
by one of those other tools will contain these values, of course, but they also will
have many, many, many other non-interested in outputs.

## Installation

Install `phrasegen` by downloading the appropriate binary for your system from
[the latest published release](https://github.com/ThatOnePasswordWas40Passwords/phrasegen/releases).

Once downloaded, copy it to a directory somewhere on your path, e.g

```bash
mkdir ~/bin
mv /path/to/download ~/bin/phrasegen
export PATH="${PATH}:${HOME}/bin" # ideally, to your shell's rc file
```

## Usage

```bash
phrasegen -h
```

e.g Generating passphrases from a movie script stored in `/tmp/script.txt`, of
exactly 4 phrases each, joined by a `-` character, without having scrubbed any
of the punctuation from the source material, and storing in an output file
to `phrases.txt`:

```bash
phrasegen -join-str "-" \
    -i /tmp/script.txt \
    -o phrases.txt \
    -size 4 \
    -only \
    -no-strip
```

Generating from a given string via CLI directly (if `-i` is not an existing file)
 and/or outputting to STDOUT is also possible (if `-o` is omitted):

```bash
phrasegen -join-str "-" \
    -i "This is a sentence I'd like to use to generate a set of passphrases against." \
    -size 3
```

Outputs to STDOUT:

```text
This
This-is
This-is-a
is
...
of-passphrases-against
passphrases
passphrases-against
against
```

## FAQs

Please submit an issue against [the repo](https://github.com/ThatOnePasswordWas40Passwords/phrasegen).
