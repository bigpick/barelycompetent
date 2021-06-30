---
title: "leetcode: 13. Roman to Integer"
description: "My solution for '13. Roman to Integer' leetcode prompt"
date: 2021-06-30T00:00:19-05:00
type:
 - post
categories:
 - leetcode
tags:
 - algorithms
 - interview-prep
 - easy
---

> Roman numerals are represented by seven different symbols: `I`, `V`, `X`, `L`, `C`, `D` and `M`.
>
> | Symbol   |      Value |
> |----------|------------|
> | I        |     1      |
> | V        |     5      |
> | X        |     10     |
> | L        |     50     |
> | C        |     100    |
> | D        |     500    |
> | M        |     1000   |
>
> For example, 2 is written as II in Roman numeral, just two one's added together. 12 is written as XII, which is simply X + II. The number 27 is written as XXVII, which is XX + V + II.
>
> Roman numerals are usually written largest to smallest from left to right. However, the numeral for four is not IIII. Instead, the number four is written as IV. Because the one is before the five we subtract it making four. The same principle applies to the number nine, which is written as IX. There are six instances where subtraction is used:
>
> `I` can be placed before `V` (5) and `X` (10) to make 4 and 9.
> `X` can be placed before `L` (50) and `C` (100) to make 40 and 90.
> `C` can be placed before `D` (500) and `M` (1000) to make 400 and 900.
>
> Given a roman numeral, convert it to an integer.

## Description / Approach

It is guranteed that our given input `s` is a valid roman numeral in the range `[1, 3999]`. An extremely naive approach could be just building a table of all possible hardcoded roman numbers, and then performing a lookup of the given value. But we are programmers, can we not do better?

Original thoughts are just to scan left to right, searching for a symbol "class", up until we hit a different class. By "class", I mean III and VI and M are each classes, reading left to right, if we hit a symbol, we know that the demarcation of that symbol is when we read the next different symbol class that's not an `I` (since for example `VII` is valid).

... However, this doesn't quite work, for the wrinkle mentioned above that sometimes we can actually have an `I` symbol before `V` and `X` (along with the other cases of substraction).

A more general approach that seems should work is the following:

* For every symbol given
* Starting at the left most digit, store the symbol at current idx as a value
  * Inspect the symbol at idx+1
     * If the symbol at current idx is less than the symbol at idx+1
        * Subtract the value of idx from the total
     * If the symbol at the current idx is greater than the symbol at idx+1
        * Add the valud of idx to the running total
  * idx += 1
* Return total

## Accepted Solutions

### Python
{{< github repo="bigpick/leetcode" file="/easy/python/000_013_roman_to_integer/solution.py" lang="python" options="linenos=true" >}}

> Runtime: 44 ms, faster than 82.58% of Python3 online submissions for Roman to Integer.
>
> Memory Usage: 14.1 MB, less than 94.52% of Python3 online submissions for Roman to Integer.

### Rust
{{< github repo="bigpick/leetcode" file="/easy/rust/src/_000_013_roman_to_integer/solution.rs" lang="python" options="linenos=true" >}}


