---
title: "Advent of Code 2021: Intro and Day One"
description: "Initial summary and first day discovery of annual Advent of Code December coding skill building."
date: 2021-12-06T09:24:19-05:00
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

What better way to work off the mental fog from month-long holiday cookie binge eating than a daily bite sized programming challenge?

This year, a few of my colleagues reported that they started working through the Advent of Code problems in one of our discord channels. I didn't pay much attention to it initially, but after about a week, the FOMO was gnawing at me too much, and I finally caved.

This is the first post in a daily series where I'll work through my thoughts on each daily challenge, and post my accepted solutions.

> ... **Can I stream my solution?** Please try to avoid giving away the solution while people are competing. If a puzzle's global daily leaderboard isn't full yet and you're likely to get points, please wait to stream/post your solution until after that leaderboard is full. If you are unlikely to get points or the daily leaderboard is already full for the puzzle you're working on, streaming is fine.

_Noted; don't be like the noobs who post CTF flags for still running CTF challenges_. So, this series will be discussing _yesterday's_ problem :)


> Your instincts tell you that in order to save Christmas, you'll need to get all **fifty stars** by December 25th.
>
> Collect stars by solving puzzles. Two puzzles will be made available on each day in the Advent calendar; the second puzzle is unlocked when you complete the first. Each puzzle grants **one star**. Good luck!

In order to "save the day" and complete the advent calendar fully, we'll need to be solving each of the two release puzzles a day, for all 25 days of December. With that, let's get started on day one!

## [--- Day 1: Sonar Sweep ---](https://adventofcode.com/2021/day/1)

### Day 1:1 Problem

> The first order of business is to figure out how quickly the depth increases, just so you know what you're dealing with - you never know if the keys will get carried into deeper water by an ocean current or a fish or something.
>
> To do this, count the number of times a depth measurement increases from the previous measurement. (There is no measurement before the first measurement.) In the example above, the changes are as follows:
>
> ```text
> 199 (N/A - no previous measurement)
> 200 (increased)
> 208 (increased)
> 210 (increased)
> 200 (decreased)
> 207 (increased)
> 240 (increased)
> 269 (increased)
> 260 (decreased)
> 263 (increased)
> ```
>
> -- In this example, there are **`7`** measurements that are larger than the previous measurement.

So, we're given a list of numbers for some unknown number of days, and we need to calculate the number of measurements that had increased from their previous one.

My initial thought is to just iterate over the given list from start to end, keeping track of three placeholder vars:

* the current depth value
* the previous depth value
* the number of depth measurement increases

Before beginning to iterate, the first two vars will have a negative value (seems to be the safest "infinite" value, as we expect to not ever have a negative depth), and the number of depth measurement increases will be zero.

For the first depth measurement, we'll update the current depth value, and then proceed to the next depth measurement; The first reading doesn't count as an increase per the prompt.

For the second up to the last depth measurement:

* read the current depth value
* compare current depth value with the previous depth value
   * if higher, increment the number of depth measurement increases
* set current depth value to previous
* proceed to next iteration

At the end, we can just return the number of depth measurement increases variable, and we're done.

Since this is the first day of challenges and the first challenge of the day, I started with a common library/file to handle some (hopefully) reused patterns, mainly validating and parsing command line values and options;

{{< highlight python "linenos=table" >}}
from argparse import ArgumentParser, ArgumentTypeError, Namespace
from os.path import exists


def valid_file(file_path: str) -> str:
    """Check whether a given path is an existent file.

    If not, raises and ArgumentTypeError, as the intended purpose of
    this helper utility is a type for an argparse argument.

    Args:
        file_path (str): The path to the file to check exists.
    """
    if not exists(file_path):
        raise ArgumentTypeError(f"{file_path} does not exist")
    return file_path


def chall_file_parser(parser: ArgumentParser) -> ArgumentParser:
    """Configure CLI parser for a single named filepath argument.

    Will raise "ArgumentTypeError" if the specified value for the named file argument does not
    exist on the local filesystem/is not accessible.

    Args:
        parser (ArgumentParser): The argument parser to configure.
    """
    parser.add_argument(
        "--chall-input",
        dest="chall_input",
        metavar="FILE",
        type=valid_file,
        required=True,
    )
    return parser


def parse_single_named_file_cli() -> Namespace:
    """Configure and parse a single named file argument from the CLI."""
    return chall_file_parser(ArgumentParser()).parse_args()


def parse_file(fpath: str) -> str:
    """Parse and return a filepath's contents.

    Args:
        fpath (str): The path to the file to parse.

    Returns:
        str: The filepath's contents.
    """
    with open(fpath, "r") as infile:
        return infile.read()
{{< /highlight >}}

The above basically makes it so that in a separate file, I'll be able to do just the following to
access the script's passed in CLI arguments, which will automatically validate that the passed in
argument for the named file is valid and able to be accessed:

```python3
from common import parse_file, parse_cli

args = parse_cli()
chall_file = parse_file(args.chall_input)
```

The pseudo code is laid out above, and is pretty straightforward. It's just a single loop with one comparison; there isn't really much to explain, so just showing the code is probably best.

### Day 1:1 solution

(as embedded from [here](https://github.com/bigpick/advent-of-code/blob/main/2021/python/day_01/depth_measurement.py)) -- Lines 15-24 (i.e function **`find_increasing_depths`**) is the solution.

{{< github repo="bigpick/advent-of-code" file="/2021/python/day_01/depth_measurement.py" lines="15-29" lang="python" options="linenostart=15,linenos=true" >}}

Running the above with our given challenge prompt file, we get `1215` as our answer:

```bash
./depth_measurement.py --chall-input day_01.txt
Day 1: Part 1: 1215
```

Which is accepted successfully on submission:

> That's the right answer! You are one gold star closer to finding the sleigh keys. [[Continue to Part Two]](https://adventofcode.com/2021/day/1#part2)

---

### Day 1:2 problem

After submitting the above solution, we gain access to the second part of day one:

> Considering every single measurement isn't as useful as you expected: there's just too much noise in the data.
>
> Instead, consider sums of a three-measurement sliding window. Again considering the above example:
>
> ```
> 199  A
> 200  A B
> 208  A B C
> 210    B C D
> 200  E   C D
> 207  E F   D
> 240  E F G
> 269    F G H
> 260      G H
> 263        H
> ```
>
> Start by comparing the first and second three-measurement windows. The measurements in the first window are marked `A (199, 200, 208)`; their sum is `199 + 200 + 208 = 607`. The second window is marked `B (200, 208, 210)`; its sum is `618`. The sum of measurements in the second window is larger than the sum of the first, so this first comparison increased.
>
> Your goal now is to count the number of times the sum of measurements in this sliding window increases from the previous sum. So, compare `A` with `B`, then compare `B` with `C`, then `C` with `D`, and so on. Stop when there aren't enough measurements left to create a new three-measurement sum.

So, now instead of simply counting from one depth measurement to the next, we need to be able to track the difference of sums between 3-reading windows. From the challenge prompt, the readings always will be in order; i.e once we see the first A, the two days after it will also belong to A. Also from the challenge prompt, we are still getting the 3-reading windows in order; the very first day marks the first reading of the first window. The second day marks the second window of the first reading, and the first day of the second window and so on.

My initial thought to approach this is like so; we should only ever have at one time a maximum of three, 3 day windows we need to track at a time (no more since the window size is only 3 days, but less when initially starting out, not being able to initialize the first group of three until the third day.

We can chunk the given depths up into groupings of three, starting from the first element and sliding the initial value of the window to the right by one, until we no longer have enough items in the given depths to form a new window of three; in Python, something like so is how I think to do it:

```python
>>> depths=[1,2,3,4,5,6,7,8,9,10,11,12,13]
>>> window_size = 3
>>> for i in range(len(depths) - window_size + 1):
...   print(depths[i:i+window_size])
...
[1, 2, 3]
[2, 3, 4]
[3, 4, 5]
[4, 5, 6]
[5, 6, 7]
[6, 7, 8]
[7, 8, 9]
[8, 9, 10]
[9, 10, 11]
[10, 11, 12]
[11, 12, 13]
```

Then, we can just compute the sums of each of those, and then use the original `find_increasing_depths` from part one to get our answer, since at that point, the format now matches the original part's format (just single values, comparing previous to the current).

### Day 1:2 solution

(as embedded from [here](https://github.com/bigpick/advent-of-code/blob/main/2021/python/day_01/depth_measurement.py)) -- Lines 32-43 (i.e function **`produce_windows` in combination with the above `find_increasing_depths`**) is the solution.

{{< github repo="bigpick/advent-of-code" file="/2021/python/day_01/depth_measurement.py" lines="32-43" lang="python" options="linenostart=32,linenos=true" >}}

Running the above with our given challenge prompt file, we get `1150` as our answer:

```bash
./depth_measurement.py --chall-input inputs/day_01.txt
...
Day 1: Part 2: 1150
```

Which is accepted successfully on submission:



> That's the right answer! You are one gold star closer to finding the sleigh keys.
>
> You have completed Day 1! You can [Share] this victory or [Return to Your Advent Calendar].

Woo! Day one down. Come back to check out tomorrow's solution!

### Full solution code

#### Python

(as embedded from [here](https://github.com/bigpick/advent-of-code/blob/main/2021/python/day_01/depth_measurement.py)):

{{< github repo="bigpick/advent-of-code" file="/2021/python/day_01/depth_measurement.py" lang="python" options="linenos=true" >}}

#### Scala

(as embedded from [here](https://github.com/bigpick/advent-of-code/blob/main/2021/scala/src/main/scala/adventofcode/Day01.scala)):

{{< github repo="bigpick/advent-of-code" file="/2021/scala/src/main/scala/adventofcode/Day01.scala" lang="scala" options="linenos=true" >}}


