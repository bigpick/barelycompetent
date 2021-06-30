---
title: "leetcode: 9. Palindrome Number"
description: "My solution for '9. Palindrome Number' leetcode prompt"
date: 2021-06-29T09:24:19-06:00
type:
 - post
categories:
 - leetcode
tags:
 - algorithms
 - interview-prep
 - easy
---

> Given an integer x, return true if x is palindrome integer.
>
> An integer is a palindrome when it reads the same backward as forward. For example, 121 is palindrome while 123 is not.

## Description / Approach

* Convert the given value to an string, so we can iterate through it as a slice using indices.
* Starting `idx` at the 0th index, up to the _len(thing)//2_-th index, non-inclusive
  * Make sure that the character at index `idx` matches the character at _len(thing)-1-idx_
    * If yes, continue (increase idx by one and repeat)
    * If not, immediately return False, is not a palindrome
* Return True

## Accepted Solution

### Python
{{< github repo="bigpick/leetcode" file="/easy/python/000_009_palindrome_number/solution.py" lang="python" options="linenos=true" >}}

> Runtime: 56 ms, faster than 79.53% of Python3 online submissions for Palindrome Number.
>
> Memory Usage: 14.3 MB, less than 13.91% of Python3 online submissions for Palindrome Number.
