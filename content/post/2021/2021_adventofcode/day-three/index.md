---
title: "Advent of Code 2021: Day Three"
description: "Thought process and solution for day three of the 2021 Advent of Code event."
date: 2021-12-07T09:44:19-05:00
url: "/advent-of-code/2021/day-three"
type:
 - post
categories:
 - Advent Of Code
tags:
 - practice
 - interview-prep
 - python
---

> [Advent of Code](https://adventofcode.com/2021/about) is an Advent calendar of small programming puzzles for a variety of skill sets and skill levels that can be solved in any programming language you like. People use them as a speed contest, interview prep, company training, university coursework, practice problems, or to challenge each other.
>
> You don't need a computer science background to participate - just a little programming knowledge and some problem solving skills will get you pretty far. Nor do you need a fancy computer; every problem has a solution that completes in at most 15 seconds on ten-year-old hardware.
>
> If you'd like to support Advent of Code, you can do so indirectly by helping to [Share] it with others, or directly via PayPal or Coinbase.
>
> Advent of Code is a registered trademark in the United States.

Welcome back for the second day of my [Advent of Code](https://adventofcode.com/2021) musings and solutions; If this is your first time reading a post in the series, be sure to [check out the full set of posts]() to see the other days' solutions. Without further ado, let's get into today's problems.

## [--- Day 3: Binary Diagnostic ---](https://adventofcode.com/2021/day/3)

### Day 3:1 problem

> The submarine has been making some odd creaking noises, so you ask it to produce a diagnostic report just in case.
>
> The diagnostic report (your puzzle input) consists of a list of binary numbers which, when decoded properly, can tell you many useful things about the conditions of the submarine. The first parameter to check is the power consumption.
>
> You need to use the binary numbers in the diagnostic report to generate two new binary numbers (called the gamma rate and the epsilon rate). The power consumption can then be found by multiplying the gamma rate by the epsilon rate.
>
> Each bit in the gamma rate can be determined by finding the most common bit in the corresponding position of all numbers in the diagnostic report. For example, given the following diagnostic report:
>
> ```
> 00100
> 11110
> 10110
> 10111
> 10101
> 01111
> 00111
> 11100
> 10000
> 11001
> 00010
> 01010
> ```

So we need to find two things, the **gamma rate** and the **epsilon rate**. As stated above, the each bit in the gamma rate is the most common (frequent) bit of each index of all the readings. Since the epsilon rate is calculated in a similar way, but with the _least common_, by finding the gamma rate, have the epsilon rate already; since it's binary, we can just flip each bit of the gamma rate to get the epsilon rate.

So, we can loop through each element of the input, and for each bit index of all the entries, just tally up whether there were more `0`'s or `1`'s at that index overall.

### Day 3:1 solution

(as embedded from [here](https://github.com/bigpick/advent-of-code/blob/main/2021/python/day_03/binary_diagnostic.py)) -- Lines 14-21 (i.e function **`most_frequent_bit`** in combination with a loop) is the solution.

{{< github repo="bigpick/advent-of-code" file="/2021/python/day_03/binary_diagnostic.py" lines="14-21" lang="python" options="linenostart=14,linenos=true" >}}

... and ...

{{< github repo="bigpick/advent-of-code" file="/2021/python/day_03/binary_diagnostic.py" lines="31-39" lang="python" options="linenostart=31,linenos=true" >}}

Running the above with our given challenge prompt file, we get `3882564` as our answer:

```bash
./python/day_03/binary_diagnostic.py --chall-input inputs/day_03.txt
Day 3 part 1: 3882564
```

Which is accepted successfully on submission:

> That's the right answer! You are one gold star closer to finding the sleigh keys. [[Continue to Part Two]](https://adventofcode.com/2021/day/3#part2)

---

### Day 3:2 problem

> Next, you should verify the life support rating, which can be determined by multiplying the oxygen generator rating by the CO2 scrubber rating.
>
> Both the oxygen generator rating and the CO2 scrubber rating are values that can be found in your diagnostic report - finding them is the tricky part. Both values are located using a similar process that involves filtering out values until only one remains. Before searching for either rating value, start with the full list of binary numbers from your diagnostic report and consider just the first bit of those numbers. Then:
>
> Keep only numbers selected by the bit criteria for the type of rating value for which you are searching. Discard numbers which do not match the bit criteria.
>
> * If you only have one number left, stop; this is the rating value for which you are searching.
> * Otherwise, repeat the process, considering the next bit to the right.
>
> The bit criteria depends on which type of rating value you want to find:
>
> To find oxygen generator rating, determine the most common value (0 or 1) in the current bit position, and keep only numbers with that bit in that position. If 0 and 1 are equally common, keep values with a 1 in the position being considered.
> To find CO2 scrubber rating, determine the least common value (0 or 1) in the current bit position, and keep only numbers with that bit in that position. If 0 and 1 are equally common, keep values with a 0 in the position being considered.

So, now we need to find the most frequent bit at a index, and then filter out any numbers that don't have the current most frequent bit at that index (and in the event of a tie, any elements who don't have a `1` at that index)

We can re-use our above function to find the most frequent bit at an index, except now we need to combine it with some additional logic to handle ties.

We can take that, and then filter out the values in the input list against the most frequent bit at the index once known. Then, we have the problem finished.

### Day 3:2 solution

(as embedded from [here](https://github.com/bigpick/advent-of-code/blob/main/2021/python/day_03/binary_diagnostic.py)):

{{< github repo="bigpick/advent-of-code" file="/2021/python/day_03/binary_diagnostic.py" lines="46-59" lang="python" options="linenostart=46,linenos=true" >}}

(`least_frequent_bit` is just a function to return the inverse of the `most_frequent_bit`):

{{< github repo="bigpick/advent-of-code" file="/2021/python/day_03/binary_diagnostic.py" lines="24-26" lang="python" options="linenostart=26,linenos=true" >}}

Running the above with our given challenge prompt file, we get `` as our answer:

```bash
./python/day_03/binary_diagnostic.py --chall-input inputs/day_03.txt
...
Day 3 part 2: 3385170
```

Which is accepted successfully on submission:

> That's the right answer! You are one gold star closer to finding the sleigh keys.
>
> You have completed Day 3! You can [Share] this victory or [Return to Your Advent Calendar].

Woo! Day two down. Come back to check out tomorrow's solution!

### Full solution code

#### Python

(as embedded from [here](https://github.com/bigpick/advent-of-code/blob/main/2021/python/day_03/binary_diagnostic.py)):

{{< github repo="bigpick/advent-of-code" file="/2021/python/day_03/binary_diagnostic.py" lang="python" options="linenos=true" >}}


#### Scala

TODO
