---
title: "Advent of Code 2022: Day 3"
date: 2022-12-03T16:45:00-00:00
url: "/advent-of-code/2022/day-three"
Description: |
  Help the elves re-organize their rucksacks! Find the duplicate items
  in each rucksack, and help the elves be on their merry way.
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

## Day three part one

For the third day, we're given input that is a list of strings. Each
string represents a "rucksack", where the individual chars in the string
represent inventory items. Each rucksack has two compartments, which
are represented by the first and second half of the rucksack (string),
respectively.

```text
vJrwpWtwJgWrhcsFMMfFFhFp
jqHRNqRjqzjGDLGLrsFMfFZSrLrFZsSL
PmmdzqPrVvPwwTWBwg
wMqvLMZHhHMvwLHjbvcjnnSBnvTQFn
ttgJtRGJQctTZtZT
CrZsJsPPZsGzwwsLwLmpwMDw
```

The first rucksack contains `vJrwpWtwJgWrhcsFMMfFFhFp`, with its first
compartment having the items `vJrwpWtwJgWr` and the second compartment
having items `hcsFMMfFFhFp`. Each item has a "priority" which is
an integer value based on the item's char:

* Lowercase item types `a` through `z` have priorities 1 through 26.
* Uppercase item types `A` through `Z` have priorities 27 through 52.

Part one asks to find the one item that appears in both
compartments, get its priority value, and then repeat and sum this process
for all given rucksacks.

### Solution

It is guaranteed that each rucksack will have two compartments, and that
they are always equal in size. It is also guaranteed that each compartment will
**always** have _exactly one_ common item.

My thought process for solving part one centered on the preceding
guarantees. Without having to worry about edge cases or special
handling, we can pretty simply find the solution as follows.

For every rucksack (line in given input):

* split rucksack into two even compartments based on line length
* convert each compartment (which is a string) into a set
* find the intersection of the two compartments
* convert the resulting single item (char) to its priority value
* sum

That looks like so (docstrings removed for brevity. To see full source,
inspect code at bottom of post):

```python
def get_common_item_priority_score(c: str) -> int:
    if c.islower():
        return ord(c) - 96

    # Account for the difference between a->Z (-32), as well as the fact
    # that we're starting at 27 and not 1 (+26)
    return (ord(c) - (96 - 32)) + 26


def line_to_rucksack(inv_line: str) -> str:
    midway = len(inv_line) // 2
    return set(inv_line[0:midway]).intersection(set(inv_line[midway:])).pop()


def find_priority_sum_each_rucksack(input: list[str]) -> int:
    return sum([get_common_item_priority_score(line_to_rucksack(line)) for line in input])
```

## Day three part two

Part two asks to find the common item across three whole rucksacks, then
find it's priority value and sum for all threesome rucksack pairings in
the given input.

The three-rucksack pairing is not a sliding window. The first three lines
of input belong to the first threesome. Lines 4, 5, and 6 belong to the
second threesome, etc.

### Solution

We no longer have to bother with splitting the rucksacks into compartments.
But, we now have to be able to generate the three-rucksack pairings.

Once we have the three rucksack pairings, we need to find the common item
amongst them, then calculate it's priority value and sum for all pairings.

We can re-use the item-to-priority function, so we just need to generate
the three-rucksack pairings, and then get the common item from them.

To get the three-rucksack pairings, I used a generator that made the
pairings using slicing and the ability to use non-single-increment sizes
in the `range()` method:

```python
def take_chunks(l: list[str], size: int) -> Iterable[list[str]]:
    for i in range(0, len(l), size):
        yield l[i : i + size]
```

To find the common item across each rucksack pairing, I decided to
once again convert each rucksack to a set, then find the intersection
of the resulting sets:

```python
def get_common_from_three_rucksacks(rucksacks: list[str]) -> str:
    return set.intersection(*list(map(set, rucksacks))).pop()  # type: ignore
```

The above is a bit dense, and I'd maybe split it for code someone other
then myself would need to maintain or if this wasn't a trivial practice
exercise.

With the two pieces in place, we can break the given input into
all three-rucksack pairings, get a common item, and convert to it's
priority value. All that is left is to actually do that, and plop it
inside a `sum()`:

```python
def find_priority_of_3sum(input: list[str]) -> int:
    return sum(
        [
            get_common_item_priority_score(get_common_from_three_rucksacks(elf_3some))
            for elf_3some in take_chunks(input, 3)
        ]
    )
```

## Python solution

The source code presented below resides in my [GitHub repository for advent of code][].

{{< github repo="bigpick/code-practice" file="/adventofcode/2022/python/src/aoc/day03.py" lang="python" options="linenos=true" >}}

[Github repository for advent of code]: <https://github.com/bigpick/code-practice/blob/main/2022/advent-of-code/python/src/aoc/day03.py>
[1]: <https://barelycompetent.dev/categories/advent-of-code/>
