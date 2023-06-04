---
title: "Timing in Python: a time.time() alternative"
date: 2023-04-08T01:24:55-05:00
url: "/python/timing-in-python-considerations"
Description: |
    Check out https://www.webucator.com/article/python-clocks-explained
    for the details.
type: posts
categories:
 - programming
tags:
 - python
---

## Background

I was going to write an article about the different methods of various `time`
utils in Python for measuring execution time and such, but in my research, I
came across the page below:

* https://www.webucator.com/article/python-clocks-explained

This basically sums up everything I would say and then some, and agrees with my
prior research thus far.

Do check out that page, as it is a good read into how and or why you should
choose which method when you want to time things in Python.

### TL;DR

Use `time.perf_counter()`.
