---
title: "Python: All slices of a list (revisted)"
date: 2024-03-26T01:24:55-05:00
url: "/misc/python/revisiting_get_all_slices_of_a_list"
Description: |
    After a brief break, I realized that my prior post on getting all slices of
    a list was really obtuse. Here's some updates that signigficantly speed up
    the performance and decrease the complexity.
type: posts
sidebar_toc: true
categories:
 - password cracking
tags:
 - python
---

## Background

In my [prior post covering the same topic](https://barelycompetent.dev/misc/python/get_all_slices_of_a_list/),
I presented some ways of achieving the outcome using various methods.

What I failed to realize at the time was that there was a significantly easier, and
significantly easier to customize, approach via a trivial sliding window approach.

### Recap

Given a sentence, generate all possible combinations of phrases possible from
that sentence while maintaining original word apperance ordering.

Clearer said, all possible slices of an original list; Given a list

```python
["a", "b", "c", "d"]
```

desired output translated into slices should be this:

```python
"a"               # slices[0:1]
"b"               # slices[1:2]
"c"               # slices[2:3]
"d"               # slices[3:4]
"a" "b"           # slices[0:2]
"b" "c"           # slices[1:3]
"c" "d"           # slices[2:4]
"a" "b" "c"       # slices[0:3]
"b" "c" "d"       # slices[1:4]
"a" "b" "c" "d"   # slices[0:4]
```

## Solution - without overthinking it

Thanks to [some fine stackoverflow folks](https://stackoverflow.com/a/30609050):

```python
def find_ngrams(input_list, n):
  return zip(*[input_list[i:] for i in range(n)])

def equivalent(input_list):
    with open("new.txt", "w") as outfile:
        for ngram_size in range(1, len(input_list)+1):
          for generated in find_ngrams(input_list, ngram_size):
            outfile.write("-".join(generated)+"\n")
```

Using this, we can just scale it across the length of the input to generate all ngrams
from 1:`len(input)`.

### Comparison

Using the prior solution:

```python
def faster_cleaner(x):
    return [x[s:e] for s, e in combinations(range(len(x)+1), 2)]

def old(x):
  with open("old.txt", "w") as outfile:
    for generated in faster_cleaner(x):
      outfile.write("-".join(generated)+"\n")
```

Timing:

```python
>>> timeit(lambda: old(x), number=1000)
9.882000374999961

>>> timeit(lambda: equivalent(x), number=1000)
12.637768542000003
```

So it is somewhat slower, but what we gain with the new capability is being able to
easily toggle the n-gram size. In the original solutions, we were always stuck with
generating _all_ n-grams from 1-`len(input)`, which wasn't always desired.

## Module

Stay tuned - I started working on a simple dedicated CLI tool to leverage this idea
to be able to generate well-ordered passphrases from an input wordlist.
