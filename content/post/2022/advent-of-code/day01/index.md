---
title: "Advent of Code 2022: Day 1"
date: 2022-12-01T13:49:00-00:00
url: "/advent-of-code/2022/day-one"
Description: |
  December is finally here, and that means so is the annual programming
  calendar Advent of Code. Join me once again this year as I work through
  the days, this time making it a bit further than I did in 2021 😅
type: posts
categories:
 - Advent Of Code
tags:
 - practice
 - interview-prep
 - python
---

## Advent of Code 2022

Today's the first day of December, which brings with it a brand new
start to the annual [Advent of Code][] programming calendar.

I attempted to follow along with doing the daily tasks last year (see
[my few posts about it][1]) but puttered out after the fourth day.

I am hoping this year to have a stricter adherence to the tasks, which
I plan on achieving by attempting to not over-engineer the (trivially
presented) tasks.

This post will serve as the first of (hopefully) twenty five, as I work
through the 2022 calendar.

If you have questions about my solutions, leave a comment below. If you
like my style, feel free to leave a star on my [GitHub repository for advent of code][]
(knowing people are looking at the things I make helps with motivation!)


## Day one part one

For the first day, we're given input that represents elves. Each "elf"
is represented by a contiguous set of strings. The strings represent
an integer, which is intended to convey the caloric value of the snack
it is representing which is contained in that elf's inventory.

We are tasked at first with finding the elf with the most amount of
calories, and returning that numerical value.

### Solution

Split the input so we have a list of "elves". For each elf, find it's
caloric sum, and add that value to a list.

Sort the list, and take the highest value.

## Day one part two

Part two asks to do the same as part one, except now it must include
the top _three_ elves' caloric value.

### Solution

Reusing the code from the first part, do exactly the same, except now
take the top 3 results from the sorted list and sum them together.

## Python solution

The source code presented below resides in my [GitHub repository for advent of code][].

{{< github repo="bigpick/code-practice" file="/adventofcode/2022/python/src/aoc/day01.py" lang="python" options="linenos=true" >}}


[Github repository for advent of code]: <https://github.com/bigpick/code-practice/blob/main/2022/advent-of-code/python/src/aoc/day01.py>
[Advent of Code]: <https://adventofcode.com/2022>
[1]: <https://barelycompetent.dev/categories/advent-of-code/>
