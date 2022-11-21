---
title: "Advent of Code 2021: Day Four"
description: "Thought process and solution for day three of the 2021 Advent of Code event."
date: 2021-12-08T09:24:19-05:00
url: "/advent-of-code/2021/day-four"
type:
 - posts
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

## Day 4: Giant Squid

(https://adventofcode.com/2021/day/4)

### Day 4:1 problem

> What you can see, however, is a giant squid that has attached itself to the outside of your submarine. ... Maybe it wants to play bingo?
>
> Bingo is played on a set of boards each consisting of a 5x5 grid of numbers. Numbers are chosen at random, and the chosen number is marked on all boards on which it appears. (Numbers may not appear on all boards.) If all numbers in any row or any column of a board are marked, that board wins. (Diagonals don't count.)
>
> ... The score of the winning board can now be calculated. Start by finding the sum of all unmarked numbers on that board; in this case, the sum is 188. Then, multiply that sum by the number that was just called when the board won, 24, to get the final score, 188 * 24 = 4512.
>
> To guarantee victory against the giant squid, figure out which board will win first. What will your final score be if you choose that board?

So, our input is an initial line of comma separated integers, which represent bingo balls being picked in order, left to right.

Then, we get an undisclosed number of bingo cards, which are represented by a 5 line, 5 column group of numbers, separated by a blank line (one blank line after the picked numbers line, and then a blank line inbetween every single card).

---

My initial thoughts are:

* Make a "Bingo Card" object for re-usability, which we will be able to create from each of the 5x5 bingo cards

Parsing the given challenge input into card objects should be easy,
since we know each card is 5 lines by 5 columns. The fact that there is
an  unknown number of cards doesn't really matter, since we can just
squash strip all the empty lines between the cards from the document,
then read every 5 lines (and associated columns) into a new Bingo Card
object until we hit the end of the document.

This parsing looks like so:

{{< github repo="bigpick/advent-of-code" file="/2021/python/day_04/bingo.py" lines="151-157" lang="python" options="linenostart=151,linenos=true" >}}

Using list comprehension in Python, we create a list of lists of length
5 from the squashed input text (sans initial "picked numbers" line); This
list of lists represents all given Bingo boards. Then, to create more
rich list, we convert the list of lists of ints to a list of BingoCard
objects, using the `BingoCard.from_str()` class method.

The BingoCard object's internals looks like so:

```python
class BingoCard:
    def __init__(self, rows: Optional[List[List[BingoSquare]]] = None):
        if not rows:
            self.card = [
                [BingoSquare()] * 5,
                [BingoSquare()] * 5,
                [BingoSquare()] * 5,
                [BingoSquare()] * 5,
                [BingoSquare()] * 5,
            ]
        else:
            self.card = rows
```

and the `.from_str()` classmethod, which parses a 5x5 text representation
of a Bingo card into an actual BingoCard object is like so:

{{< github repo="bigpick/advent-of-code" file="/2021/python/day_04/bingo.py" lines="116-135" lang="python" options="linenostart=116,linenos=true" >}}

The `from_str()` classmethod is populating the `BingoCard` object with
`BingoSquare`s, rather than simple `int`s. This is so that we can have
additional attributes to track on a square (like if the number has been
picked yet or not). This structure is essentially a layer on top of a
dictionary, which has a value key for the square's integer value, and
also a marked key, which reprsents whether the value has been selected
in the game so far. As such, the full `BingoSquare` object is pretty
simple:

```python
class BingoSquare:
    def __init__(self, value: int = -1, marked: bool = False) -> None:
        self.box = {"value": value, "marked": marked}

    def __repr__(self) -> str:
        return dumps(self.__dict__)

    def __str__(self) -> str:
        return dumps(self.__dict__)

    def set_value(self, val: int) -> None:
        self.box["value"] = val

    def mark(self, val: int) -> None:
        if self.box["value"] == val:
            self.box["marked"] = True

    def get(self) -> dict[str, int | bool]:
        return self.box
```

The default value for a `BingoSquare` is an **unmarked, -1**. It being
unmarked is an obvious default, and -1 seemed like the most sane default
value as the input implicity declared there are no negative game values,
so anything less than zero is clearly not valid yet.

So, now we've parsed all selected numbers, and established all of our
given Bingo boards into rich `BingoCard`s. Now, we need to actually mark
off the cards based on the list of selected numbers we've been given;
For today's problem, we are being asked to _figure out which board will
win first. What will your final score be if you choose that board?_

### Day 4:1 solution

(as embedded from [here](https://github.com/bigpick/advent-of-code/blob/main/2021/python/day_04/bingo.py)).

{{< github repo="bigpick/advent-of-code" file="/2021/python/day_04/bingo.py" lines="158-167" lang="python" options="linenostart=158,linenos=true" >}}

The bulk of the work is accomplished by leveraging the pre-established
`BingoCard` objects, and their respective `BingoSquare`'s classmethods.

The `find_all_bingos()` function basically just works left to right through
all given picked numbers, and attempts marks off every single card in order
from top to bottom (not moving on to the next picked number until it's
attempted to mark off all cards). Since we've read the inputs into lists
and not shuffled them, the ordering will be preserved, so iterating through
values left to right and top to bottom like this will work fine for "finding
the first winning board".

{{< github repo="bigpick/advent-of-code" file="/2021/python/day_04/bingo.py" lines="138-147" lang="python" options="linenostart=138,linenos=true" >}}

So, as mentioned, it works through all picked numbers in order,

```python
    for num in picked_nums:
```

Then all cards in order,

```python
        for card in boards:
```

Then attempts to mark off the picked number on the board. While doing
this step, it also checks to make sure that the board has not accomplished
a "bingo" after having marked off the new number:

```python
            (bingo, score) = card.mark(num)
            if bingo and card not in [x[2] for x in bingos]:
                bingos.append((score, num, card))
```

The checking logic is accomplished as part of the card's `.mark()` method:

```python
class BingoCard:
    # ...

    def mark(self, val: int) -> Tuple[bool, int]:
        """Attempt to mark a value off the card.
        Args:
            val (int): The value to search and mark off the card.
        Returns:
            Tuple[bool, int]: Whether or not the card has bingo after
                potentially marking off the value.
        """
        # Try to mark a num
        _ = [cardd.mark(val) for row in self.card for cardd in row]
        return self.has_bingo()
```

After potentially marking off the number on the card, the `mark()` function
returns the value of a call to another of it's classmethods, `has_bingo()`;
This function checks a given `BingoCard` object to see if it has any
bingoes. A bingo occurs when all values have a `"marked": true` value for
any given column, row, or diagonal (top left to bottom right, or bottom
left to top right).

{{< github repo="bigpick/advent-of-code" file="/2021/python/day_04/bingo.py" lines="78-105" lang="python" options="linenostart=78,linenos=true" >}}

Rather than trying to come up with a clever way of doing diagonals, I
simply enumerated the indices of each diagonal's coordinates (lines 85,
86).

Since the challenge asks for the "score" of a winning bingo card, when
determining if a BingoCard has any bingos, we also want to be able to grab
the score (sum of all unpicked values) of the card at the same time. This
is accomplished by calling yet another `BingoCard` classmethod, `sum_all_unchecked()`
when a bingo is detected (e.g., line 95 or 103).

The `sum_all_unchecked()` function is trivial, since we already have the
card reference; it's just a matter of iterating through all `BingoSquare`s
within the `BingoCard` and summing any entry whose `marked` value is false:

```python
    def sum_all_unchecked(self) -> int:
        """Return the sum of all unchecked bingo squares."""
        sum = 0
        for row in self.card:
            for card in row:
                box = card.get()
                sum += box["value"] if not box["marked"] else 0
        return sum
```

Running the above with our given challenge prompt file, we get `58838` as our answer:

```bash
./bingo.py --chall-input ../../inputs/day_04.txt
First BINGO!!! Unmarked: 806 || Last Drawn: 73 || Score: 58838
```

Which is accepted successfully on submission:

> That's the right answer! You are one gold star closer to finding the sleigh keys. [[Continue to Part Two]](https://adventofcode.com/2021/day/4#part2)

---

### Day 4:2 problem

> On the other hand, it might be wise to try a different strategy: let the giant squid win ... the safe thing to do is to figure out which board will win last and choose that one. That way, no matter which boards it picks, it will win for sure.

### Day 4:2 solution

(as embedded from [here](https://github.com/bigpick/advent-of-code/blob/main/2021/python/day_04/bingo.py)).

Since the way [we accomplished the first part of the day's solution](#day-41-solution)
operated on keeping proper order, we can re-use the same code, except
of taking the _first_ BingoCard we find with a score, we want the last.

Running the above with our given challenge prompt file, we get `` as our answer:

```bash
./bingo.py --chall-input ../../inputs/day_04.txt
# ...
Last BINGO!!! Unmarked: 136 || Last Drawn: 46 || Score: 6256
```

Which is accepted successfully on submission:

> That's the right answer! You are one gold star closer to finding the sleigh keys.
>
> You have completed Day 4! You can [Share] this victory or [Return to Your Advent Calendar].

Woo! Day four down. Come back to check out tomorrow's solution!

### Full solution code

#### Python

Full source available [here](https://github.com/bigpick/advent-of-code/blob/main/2021/python/day_04/bingo.py) (not linked, since mostly snippeted above).

#### Scala

TODO

