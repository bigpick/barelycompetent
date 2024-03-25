---
title: "Python: Printing all permutations of list while maintaining order and sequence (all slices of a list)"
date: 2024-03-25T01:24:55-05:00
url: "/misc/python/get_all_slices_of_a_list"
Description: |
    Snippet of some code I messed with during a password cracking portion of a CTF; good
    for generating a list of all possible passwords in order given a source set of words.
type: posts
sidebar_toc: true
categories:
 - password cracking
tags:
 - python
---

## Background

Given a sentence, generate all possible combinations of phrases possible from that sentence
while maintaining original word apperance ordering.

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

## Solution

### Naive

```python
password_sentence_candidate = "Who controls the past controls the future. Who controls the present controls the past.".split()
generated = []
max_size = len(password_sentence_candidate)

for size in range(max_size, 0, -1):
    for start in range(max_size-size+1):
      generated.append(password_sentence_candidate[start:start+size])

print(generated)
```

### Faster

```python
def faster(x):
    return list(map(x.__getitem__, starmap(slice, combinations(range(len(x)+1), 2))))

def faster_cleaner(x):
    return [x[s:e] for s, e in combinations(range(len(x)+1), 2)]
```

Timing:

```python
>>> timeit.timeit(lambda: naive(x), number=1000000)
10.688588707999997

>>> timeit.timeit(lambda: faster(x), number=1000000)
7.675131582999995

>>> timeit.timeit(lambda: faster_cleaner(x), number=1000000)
7.348017374999927
```

Using a larger input:

```python
>>> x = "It could not have been ten seconds, and yet it seemed a long time that their hands were clasped together.  He had time to learn every detail of her hand.  He explored the long fingers, the shapely nails, the work-hardened palm with its row of callouses, the smooth flesh under the wrist.  Merely from feeling it he would have known it by sight.  In the same instant it occurred to him that he did not know what colour the girl's eyes were.  They were probably brown, but people with dark hair sometimes had blue eyes.  To turn his head and look at her would have been inconceivable folly.  With hands locked together, invisible among the press of bodies, they stared steadily in front of them, and instead of the eyes of the girl, the eyes of the aged prisoner gazed mournfully at Winston out of nests of hair.".split()

>>> len(x)
148

>>> timeit.timeit(lambda: naive(x), number=10000)
19.782310624999923

>>> timeit.timeit(lambda: faster(x), number=10000)
18.402811583000016

>>> timeit.timeit(lambda: faster_cleaner(x), number=10000)
18.572308792000058
```

So, the "faster" solutions show some slightly better performance, but
cleanliness/readability trade-off is up to you.

### Generator

```python
from typing import Generator

def ordered_combos(input_phrase: str) -> Generator[str, None, None]:
    for size in range(len(password_sentence_candidate),0,-1):
        for start in range(len(password_sentence_candidate)-size+1):
            yield password_sentence_candidate[start:start+size]

password_sentence_candidate = "Who controls the past controls the future. Who controls the present controls the past.".split()

for gen_phrase in ordered_combos(password_sentence_candidate):
    print(gen_phrase)

# ['Who', 'controls', 'the', 'past', 'controls', 'the', 'future.', 'Who', 'controls', 'the', 'present', 'controls', 'the', 'past.']
# ['Who', 'controls', 'the', 'past', 'controls', 'the', 'future.', 'Who', 'controls', 'the', 'present', 'controls', 'the']
# ...
```

#### Joining based on separator

```python
from typing import Generator

def ordered_combos(input_phrase: str, joiner: str) -> Generator[str, None, None]:
    for size in range(len(password_sentence_candidate),0,-1):
        for start in range(len(password_sentence_candidate)-size+1):
            yield joiner.join(password_sentence_candidate[start:start+size])

password_sentence_candidate = "Who controls the past controls the future. Who controls the present controls the past.".split()

for gen_phrase in ordered_combos(password_sentence_candidate, "-"):
    print(gen_phrase)

# Who-controls-the-past-controls-the-future.-Who-controls-the-present-controls-the-past.
# Who-controls-the-past-controls-the-future.-Who-controls-the-present-controls-the
# controls-the-past-controls-the-future.-Who-controls-the-present-controls-the-past.
# Who-controls-the-past-controls-the-future.-Who-controls-the-present-controls
# ...
```

#### Joining based on separator scrubbing punctuation

```python
from typing import Generator
import string

def ordered_combos(input_phrase: str, joiner: str) -> Generator[str, None, None]:
    for size in range(len(password_sentence_candidate),0,-1):
        for start in range(len(password_sentence_candidate)-size+1):
            yield joiner.join([w.translate(str.maketrans('', '', string.punctuation)) for w in password_sentence_candidate[start:start+size]])

password_sentence_candidate = "Who controls the past controls the future. Who controls the present controls the past.".split()

for gen_phrase in ordered_combos(password_sentence_candidate, "-"):
    print(gen_phrase)

# Who-controls-the-past-controls-the-future-Who-controls-the-present-controls-the-past
# Who-controls-the-past-controls-the-future-Who-controls-the-present-controls-the
# controls-the-past-controls-the-future-Who-controls-the-present-controls-the-past
# Who-controls-the-past-controls-the-future-Who-controls-the-present-controls
# controls-the-past-controls-the-future-Who-controls-the-present-controls-the
# ...
```

## All together

I think I might have to write a module/package that does this, with some nice CLI
options. Stay tuned :)
