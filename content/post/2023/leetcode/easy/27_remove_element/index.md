---
title: "leetcode #27 (easy): Remove Element"
date: 2023-06-08T01:24:55-05:00
url: "/leetcode/easy/27-remove-element"
Description: |
    Given an integer array nums and an integer val, remove all
    occurrences of val in nums in-place. The order of the elements may
    be changed. Then return the number of elements in nums which are not
    equal to val.
type: posts
categories:
 - leetcode
tags:
 - python
---

## Description / approach

Iterate backwards through the array, and use `del` on the index if we
find a matching value. Keep track of non-deleted values along the way for
`k`.

## Accepted solutions

### Python

Included source code snippet from
[https://github.com/bigpick/leetcode](https://github.com/bigpick/leetcode/blob/main/easy/python/000_027_remove_element/solution.py):

{{< github repo="bigpick/leetcode" file="/easy/python/000_027_remove_element/solution.py" lang="python" options="linenos=true" >}}
