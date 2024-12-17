---
title: "Simple Python Library for indented printing"
date: 2024-12-17T11:00:00-00:01
url: "/one-offs/python-indented-print-library"
Description: |
    A trivial Python library for simple automatic (or manual) indented printing.
type: posts
sidebar_toc: false
categories:
 - one-offs
tags:
 - python
 - plox
---

Visit: <https://codeplox-dev.github.io/plox-pyprint-indent/>

Alternatively, check out the GitHub repo at:
* <https://github.com/codeplox-dev/plox-pyprint-indent>

```python
from plox.print.indent_print import indent_print as printi


def test():
    printi("inside test")

def test2():
    printi("inside test2")
    test()

def test3():
    printi("This it the inside of test3")
    test2()
    test()


test3()
```

Outputs:

```text
|- test3():This it the inside of test3
|- |- test2():inside test2
|- |- |- test():inside test
|- |- test():inside test
```
