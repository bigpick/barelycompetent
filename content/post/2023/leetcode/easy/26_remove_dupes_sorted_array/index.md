---
title: "leetcode #26 (easy): Remove duplicates in sorted array (in-place)"
date: 2023-06-07T04:24:55-05:00
url: "/leetcode/easy/26-remove-dupes-in-sorted-array-in-place"
Description: |
    Given an integer array nums sorted in non-decreasing order, remove the
    duplicates in-place such that each unique element appears only once.

type: posts
categories:
 - leetcode
tags:
 - python
---

## Description / approach

Originally, I was just going to convert to set then back to list then return the
length, which is how I would otherwise solve this problem.

However, the description clearly stated we had to do so **in-place**.

To satisfy the above, and since it didn't matter what existed _after_ the
required elements, I thought of going backwards through the array, deleting
duplicate items.

## Accepted solutions

### Python

Included source code snippet from
[https://github.com/bigpick/leetcode](https://github.com/bigpick/leetcode/blob/main/easy/python/000_026_remove_dupes_sorted_array/solution.py):

{{< github repo="bigpick/leetcode" file="/easy/python/000_026_remove_dupes_sorted_array/solution.py" lang="python" options="linenos=true" >}}
