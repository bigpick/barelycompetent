---
title: "Advent of Code 2022: Day 2"
date: 2022-12-01T13:49:00-00:00
url: "/advent-of-code/2022/day-two"
Description: |
  The elves are back, and this time they're apparently vacationing on
  a beach. Help who gets to be nearest the snacks by determining their
  fate in a Rock, Paper, Scissors tournament.
type: posts
categories:
 - Advent Of Code
tags:
 - practice
 - interview-prep
 - python
---

## Advent of Code 2022

> Reminder: This post is part of a series I try to do each year covering
> the annual [Advent of Code][1] programming advent calendar. Check out
> the other posts in this series to see the other days, or previous
> years.

## Day two part one

For the second day, we're given input that consists of two columns. The
first column has values `A`, `B`, or `C`. The second column has values
`X`, `Y`, or `Z`. For part one, these mean the following:

* A or X mean "rock"
* B or Y mean "paper"
* C or Z mean "scissors

The task for the first part is to find the total score of the set of
games. Each line in the input file represents a game. Scoring is as
follows:

* win = 6 points
* tie = 3 points
* loss = 0 points

_What_ you play also affects your score:

* rock = 1 points
* paper = 2 points
* scissors = 3 points

### Solution

Since the possible set of outcomes is small, and not expected to change,
I figured a dictionary of the possible RPS game outcomes along with
another dictionary with the moves and their point values would be the
most straightforward and fastest way to achieve part one.

Dictionary lookups are O(1), and we need to iterate over every possible
game at least once, so we can achieve O(n).

The approach I settled on was, the following:

For every line ("game") in the input,

* read the first and second player's inputs into vars (line 55)
* dict lookup using the player1 move concated to the player2 move to
  get the outcome of the game (line 57 concats for convenience, part of 60 does lookup)
* return the dict lookup of the game outcome's score value added to the
  dict lookup of the player2's move value to a running sum (line 60)

{{< github repo="bigpick/code-practice" lines="54-67" file="/adventofcode/2022/python/src/aoc/day02.py" lang="python" options="linenostart=54,linenos=true" >}}


## Day two part two

Apparently, the second column represents the desired outcome of the
game, _not_ your intended move. The task now is to find the proper move
to achieve the intended outcome, and then once done, re-calculate our
final score should we play according to the intended outcomes.

Instead of X/Y/Z meaning R/P/S, they now mean:

* X = loss
* Y = tie
* Z = win

As a dict:

```python
expected_outcomes = {"X": "loss", "Y": "tie", "Z": "win"}
```

### Solution

Instead of rewriting the first part to also work for the second part,
I just started a new class (`FixedRPSGame`). My overall approach was to
be the same (majority of the work being dict lookups), but I needed to
add a wrinkle to find the "correct" move first before I could calculate
a game's point value.

To do this, I added one more dictionary. The dictionary has two levels,
The first key representing the desired outcome (`X`/`Y`/`Z`), and the
second level representing the required game (key representing the player1
move, value representing player2's required move to achieve the top level
outcome).

With the above wrinkle, my process as pseudo code now went along the following.

For every line ("game") in the input,

* read the first player's input and the desired outcome into vars
* for every key in the outcomes dict:
   * if the key starts with player1's same move, and the outcome of the
     key's value matches the intended outcome, return the key
* with the found key, dict lookup the score of the move being played (
  the latter half of the key, since the key represents player1's move
  pre-pended to player2's move, see line 32 below), add it to the value
  of the expected outcome of the game, and sum

{{< github repo="bigpick/code-practice" lines="70-85" file="/adventofcode/2022/python/src/aoc/day02.py" lang="python" options="linenostart=70,linenos=true" >}}

## Python solution

The source code presented below resides in my [GitHub repository for advent of code][].

{{< github repo="bigpick/code-practice" file="/adventofcode/2022/python/src/aoc/day02.py" lang="python" options="linenos=true" >}}


[Github repository for advent of code]: <https://github.com/bigpick/code-practice/blob/main/2022/advent-of-code/python/src/aoc/day01.py>
[1]: <https://barelycompetent.dev/categories/advent-of-code/>
