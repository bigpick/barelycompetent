---
title: "leetcode: 7. Reverse Integer"
description: "My solution for '7. Reverse Integer' leetcode prompt"
date: 2021-06-29T09:24:19-05:00
url: "/leetcode/problem-7-reverse-integer"
type:
 - post
categories:
 - LeetCode
tags:
 - algorithms
 - interview-prep
 - python
---

> Given a signed 32-bit integer x, return x with its digits reversed. If reversing x causes the value to go outside the signed 32-bit integer range [-231, 231 - 1], then return 0.
>
> Assume the environment does not allow you to store 64-bit integers (signed or unsigned).

## Description / approach

Using python, convert the given value to a `str`, so that we can use a slice to just reverse the value. Then convert back into an `int`, check for overflow, and then return appropriately.

## Accepted solution

### Python
{{< github repo="bigpick/leetcode" file="/easy/python/000_007_reverse_integer/solution.py" lang="python" options="linenos=true" >}}

> * Runtime: 20 ms, faster than 99.48% of Python3 online submissions for Reverse Integer.
>
> * Memory Usage: 14.2 MB, less than 43.02% of Python3 online submissions for Reverse Integer.


