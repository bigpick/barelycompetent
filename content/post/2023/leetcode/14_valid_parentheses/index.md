---
title: "leetcode #14 (easy): Valid Parentheses"
date: 2023-06-06T01:24:55-05:00
url: "/leetcode/easy/14-valid-parentheses"
Description: |
    Given a string s containing just the characters '(', ')', '{', '}', '[' and ']',
    determine if the input string is valid.
type: posts
categories:
 - leetcode
tags:
 - python
---

## Description / approach

Use a stack to keep track of last seen, and add/pop accordingly.

For all items in the input:

* If we see an "opener", add to stack and continue.
* If we see a "closer":
   * If the stack has no items, return `False` because we know there can't be a matching opening
   * Else, pop the last item from the stack.
      * If it matches the pairing for the input, continue, else return `False`.

At the end of all input, if the stack still has items (openers missing closers), return `False`, else, return `True`.


## Accepted solutions

### Python

Included source code snippet from
[https://github.com/bigpick/leetcode](https://github.com/bigpick/leetcode/blob/main/easy/python/000_0020_valid_parentheses/solution.py):

{{< github repo="bigpick/leetcode" file="/easy/python/000_0020_valid_parentheses/solution.py" lang="python" options="linenos=true" >}}
