---
title: "Advent of Code 2021: Day Two"
description: "Thought process and solution for day two of the 2021 Advent of Code event."
date: 2021-12-07T09:24:19-05:00
type:
 - post
categories:
 - Advent Of Code
tags:
 - practice
 - interview-prep
---

> [Advent of Code](https://adventofcode.com/2021/about) is an Advent calendar of small programming puzzles for a variety of skill sets and skill levels that can be solved in any programming language you like. People use them as a speed contest, interview prep, company training, university coursework, practice problems, or to challenge each other.
>
> You don't need a computer science background to participate - just a little programming knowledge and some problem solving skills will get you pretty far. Nor do you need a fancy computer; every problem has a solution that completes in at most 15 seconds on ten-year-old hardware.
>
> If you'd like to support Advent of Code, you can do so indirectly by helping to [Share] it with others, or directly via PayPal or Coinbase.
>
> Advent of Code is a registered trademark in the United States.

Welcome back for the second day of my [Advent of Code](https://adventofcode.com/2021) musings and solutions; If this is your first time reading a post in the series, be sure to [check out the full set of posts]() to see the other days' solutions. Without further ado, let's get into today's problems.

## [--- Day 2: Dive! ---](https://adventofcode.com/2021/day/2)

### Day 2:1 problem

> Now, you need to figure out how to pilot this thing.
>
> It seems like the submarine can take a series of commands like forward 1, down 2, or up 3:
>
> * forward X increases the horizontal position by X units.
> * down X increases the depth by X units.
> * up X decreases the depth by X units.
>
> The submarine seems to already have a planned course (your puzzle input). You should probably figure out where it's going. For example:
>
> ``````
> forward 5
> down 5
> forward 8
> up 3
> down 8
> forward 2
> ``````
>
> Your horizontal position and depth both start at 0 ... After following these instructions, you would have a horizontal position of 15 and a depth of 10. (Multiplying these together produces 150.)
>
> Calculate the horizontal position and depth you would have after following the planned course. What do you get if you multiply your final horizontal position by your final depth?

We need to implement some logic that can handle three commands (`forward`, `down`, `up`) and their implication on our ships location (which starts at `(0,0)`). The ship apparently never moves left/backward, so I guess _all gas no brakes_? Anyhow, to achieve this, the way I thought of initially:

* have a holder variable for the ships x distance, init w/0
* have a holder variable for the ships y distance, init w/0
* loop through instructions, matching keyword
   * if `forward`
      * add distance to x var, move to next command
   * if `up`
      * decrement distance from y var, move to next command
   * if `down`
      * add distance to y var, move to next command
* after all commands, multiple x * y

Since Python [recently](https://docs.python.org/3/whatsnew/3.10.html) introduced [Structural Pattern Matching](https://www.python.org/dev/peps/pep-0636/), I figured I'd use that as a means to achieve the `if ...` command handling logic.

### Day 2:1 solution

(as embedded from [here](https://github.com/bigpick/advent-of-code/blob/main/2021/python/day_02/movement_control.py)) -- Lines 13-36 (i.e function **`handle_movements`**) is the solution.

{{< github repo="bigpick/advent-of-code" file="/2021/python/day_02/movement_control.py" lines="13-36" lang="python" options="linenostart=13,linenos=true" >}}

Running the above with our given challenge prompt file, we get `1451208` as our answer:

```bash
./movement_control.py --chall-input inputs/day_02.txt
Day 2 part 1: 1451208
...
```

Which is accepted successfully on submission:

> That's the right answer! You are one gold star closer to finding the sleigh keys. [[Continue to Part Two]](https://adventofcode.com/2021/day/2#part2)

---

### Day 2:2 problem

> In addition to horizontal position and depth, you'll also need to track a third value, **_aim_**, which also starts at 0. The commands also mean something entirely different than you first thought:
>
> * down X increases your aim by X units.
> * up X decreases your aim by X units.
> * forward X does two things:
>    * It increases your horizontal position by X units.
>    * It increases your depth by your aim multiplied by X.

So now we need to track `(x, y, aim)`; here `aim` is akin to a tilt of the submarine. Submarines don't magically hover through the water, and instead rely on a propeller in the rear of the ship to propel it forwards in the direction it is facing. This "aim" metric is more similar to how an actual submarine would move.

The process for finding our movement is still simple, and I decided to use pattern matching once more, except now we need to include logic for updating aim on `up`/`down` commands and changing depth calculations to be included as part of the `forward` command.


### Day 2:2 solution

(as embedded from [here](https://github.com/bigpick/advent-of-code/blob/main/2021/python/day_02/movement_control.py)) -- Lines 39-56 (i.e function **`handle_movements_with_aim`**).

{{< github repo="bigpick/advent-of-code" file="/2021/python/day_02/movement_control.py" lines="39-56" lang="python" options="linenostart=39,linenos=true" >}}

Running the above with our given challenge prompt file, we get `1620141160` as our answer:

```bash
./movement_control.py --chall-input inputs/day_02.txt
...
Day 2 part 1: 1620141160
```

Which is accepted successfully on submission:


> That's the right answer! You are one gold star closer to finding the sleigh keys.
>
> You have completed Day 2! You can [Share] this victory or [Return to Your Advent Calendar].

Woo! Day two down. Come back to check out tomorrow's solution!

### Full solution code

(as embedded from [here](https://github.com/bigpick/advent-of-code/blob/main/2021/python/day_02/movement_control.py)):

{{< github repo="bigpick/advent-of-code" file="/2021/python/day_02/movement_control.py" lang="python" options="linenos=true" >}}
