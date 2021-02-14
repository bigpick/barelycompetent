---
title: "Game time! Classic interview coin question"
excerpt: "pwnable.kr challenge: coin"
date: 2020-03-18T09:24:19-05:00
categories:
 - pwn practice
---

# pwnable.kr: Intro to Binary Search: Coin Weigh Game

> Mommy, I wanna play a game!
>
> (if your network response time is too slow, try nc 0 9007 inside pwnable.kr server)
>
> Running at : `nc pwnable.kr 9007`

## Given

All we're given in this is an endpoint where the file is running.


The text hint and the title of the challenge suggest that we will be playing some sort of game (possibly impeeded by network response time?)

## Run it

```bash
nc pwnable.kr 9007

	---------------------------------------------------
	-              Shall we play a game?              -
	---------------------------------------------------

	You have given some gold coins in your hand
	however, there is one counterfeit coin among them
	counterfeit coin looks exactly same as real coin
	however, its weight is different from real one
	real coin weighs 10, counterfeit coin weighes 9
	help me to find the counterfeit coin with a scale
	if you find 100 counterfeit coins, you will get reward :)
	FYI, you have 60 seconds.

	- How to play -
	1. you get a number of coins (N) and number of chances (C)
	2. then you specify a set of index numbers of coins to be weighed
	3. you get the weight information
	4. 2~3 repeats C time, then you give the answer

	- Example -
	[Server] N=4 C=2 	# find counterfeit among 4 coins with 2 trial
	[Client] 0 1 		# weigh first and second coin
	[Server] 20			# scale result : 20
	[Client] 3			# weigh fourth coin
	[Server] 10			# scale result : 10
	[Client] 2 			# counterfeit coin is third!
	[Server] Correct!

	- Ready? starting in 3 sec... -
```

OK - so it is a game. Looks like it's of the format where we have to pass X many rounds in a time limit to get the flag.

The time limit combined with the nature of the task would be impossible to do by hand. So we're going to want to use something like pwntools to automatically send our responses based on parsing the received input.

## Rules

Looking at the game rules, it consists of 100 rounds (we have to find one counterfeit coin per round, and we have to find 100 counterfeit coins.

A round starts with a string that looks like

```bash
N=xxx C=yyy
```

Where `xxx` is the total number of coins in the heap, and `yyy` is our allowable trials.

A response looks like so:

```bash
a b c d e f g
```

Where `a`, `b`, `c`, etc... are indices of coins we want to weigh (starts at 0 being first coin).

A response to that will be a single digit, representing the weight of the coins.

This is repeated `yyy` times. Afterwhich, we pass it the index of the counterfeit coin.

If right, we get:

```bash
Correct!
```

Else:

```bash
Wrong coin!
(quits)
```

## Algorithm

This reminds me of one of those interview questions that's supposed to be seeing your approach to the problem rather than whether or not you get the answer correct.

In our case, we'll do both :)

I wrote some pseudo code/thought process out:

&nbsp;
{{< image src="/img/coin_pseudo_code.jpg" alt="Coin bin search psuedo code" position="center" style="border-radius: 8px;" >}}
&nbsp;

The implementation is up to the reader as an excercise. (Though my implementation is [here](https://github.com/bigpick/CaptureTheFlagCode/blob/master/practice/pwnable.kr/toddlersbottle/11_coin1/coin_pwn.py))

Running it:

```bash
./coin_pwn.py
[+] Opening connection to pwnable.kr on port 9007: Done
Round: 0
Round: 1
Round: 2
Round: 3
Round: 4
Round: 5
Round: 6
Round: 7
Round: 8
Round: 9
Round: 10
Round: 11
Round: 12
Round: 13
Round: 14
Round: 15
Round: 16
Round: 17
Round: 18
Round: 19
Round: 20
Round: 21
Round: 22
Round: 23
Round: 24
Round: 25
Round: 26
Round: 27
Round: 28
Round: 29
Round: 30
Round: 31
Round: 32
Round: 33
Round: 34
Round: 35
Round: 36
Round: 37
Round: 38
Round: 39
Round: 40
Round: 41
Round: 42
Round: 43
Round: 44
Round: 45
Round: 46
Round: 47
Round: 48
Round: 49
Round: 50
Round: 51
Round: 52
Round: 53
Round: 54
Round: 55
Round: 56
Round: 57
Round: 58
Round: 59
Round: 60
Round: 61
Round: 62
Round: 63
Round: 64
Round: 65
Round: 66
Round: 67
Round: 68
Round: 69
Round: 70
Round: 71
Round: 72
Round: 73
Round: 74
Round: 75
Round: 76
Round: 77
Round: 78
Round: 79
Round: 80
Round: 81
Round: 82
Round: 83
Round: 84
Round: 85
Round: 86
Round: 87
Round: 88
Round: 89
Round: 90
Round: 91
Round: 92
Round: 93
Round: 94
Round: 95
Round: 96
Round: 97
Round: 98
Round: 99
Correct! (99)

Congrats! get your flag

b1NaRy_S34rch1nG_1s_3asy_p3asy
```

Woo! Flag is `b1NaRy_S34rch1nG_1s_3asy_p3asy`.
