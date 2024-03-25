---
title: "Python type checking in VS Code: Not as nice as you'd hope"
date: 2024-03-24T01:24:55-05:00
url: "/misc/career/python/vscode_mypy_woes"
Description: |
    Similar to how other VS code extensions work out of the box, I was hoping we'd
    be able to leverage mypy as easily as all our other integrations. To my surprise,
    getting the tool working close to how we've been able to use via the CLI was more
    work than I initially thought. Here's a TL;DR of my findings.
type: posts
sidebar_toc: true
categories:
 - career
tags:
 - career
---

## Background

[mypy](https://mypy-lang.org/) provides static type checking for Python code bases:

> Mypy is an optional static type checker for Python that aims to combine the benefits
> of dynamic (or "duck") typing and static typing. Mypy combines the expressive power
> and convenience of Python with a powerful type system and compile-time type checking.
> Mypy type checks standard Python programs; run them using any Python VM with
> basically no runtime overhead.

A very trivial example from their site, for reference:

```python
def fib(n):
    a, b = 0, 1
    while a < n:
        yield a
        a, b = b, a+b
```

vs

```python
def fib(n: int) -> Iterator[int]:
    a, b = 0, 1
    while a < n:
        yield a
        a, b = b, a+b
```

Being able to provide optional type hints to a traditionally dynamic/non-typed language
like Python is a hot topic; This post doesn't cover the argument of whether one should
even consider providing or even attempting to provide type hints for Python code. There
are tons of opinions out there, and all sorts of good arguments both for and against. We've
obviously decided we are part of the "for" team, the reasons for which are not relevant
to this post.

### The problem

As part of our standardization as a team around trying to unify our development editing
around VS Code, the integration of our existing tool procedures is a big requirement.

For most extensions, they "just work" as one would expect. For example, installing the
[ruff](https://marketplace.visualstudio.com/items?itemName=charliermarsh.ruff) extension automatically
picks up our common `ruff.toml` file; Tasks automatically appear in the command palette
and function as expected; formatting and liniting automatically matches that of the
CLI tool invocation, in both performance and results. Any and everything one would have
already worked out and been using in the command line tool worked as expected right away
via the extension within VS Code.

When attempting to integrate with mypy though, we ran into some surprising problems.

## The battle of the extensions

First of all, searching in the VS Code extensions marketplace for **mypy**, you will notice
that there seemingly _two_ "legitimate" offerings:

* "[mypy](https://marketplace.visualstudio.com/items?itemName=matangover.mypy)": Type checking for Python using mypy by **_Matan Grover_**
* "[Mypy Type Checker](https://marketplace.visualstudio.com/items?itemName=ms-python.mypy-type-checker)": Type checking support for Python files using Mypy by **_Microsoft_**.

Despite having used the former previously, it was decided that standardizing around the latter
(as it is an official MS published product) was probably the better option.

For all our past extensions, the "clear, legitimate" choice was clear - the top extension
result was _clearly_ ahead of any other 3rd part extension in terms of both downloads and
ratings/reviews. We found it interesting that it wasn't the case with `mypy` however
(especially given that the 3rd party offering seemed to be the superior choice; As of the
writing of this article, the two extenions had almost the same number of downloads, and
the one by Matan had significantly higher ratings).

## Official means best, right?

Despite switching to the "more official" extension, our problems didn't magically
go away. In fact - things got much worse, to the point that just getting results from
the code base no longer worked; the extension seemed to hang indefinitely.

After a lengthy process of messing with settings and looking through the
[exisiting issues backlog](https://github.com/microsoft/vscode-mypy/issues), it became
more and more clear that all our problems with the extension seemed to stem from the
mypy daemon itself. For now (2024/03), it seems the best course of action is simply
disabling the daemon entirely, via `preferDaemon: false`.

Below is a snippet of our relevant common VS code settings with such a statement, along
with some other values that we found increased performance of scanning speed (with a
large improvement coming from ignoring as much as non-required items as possible):

```json
    "mypy-type-checker.ignorePatterns": [
        ".direnv/*",
        "docs/*",
        "*generated/*",
        "*<common-submodule-name>/*",
        "*cache*",
        "dist*"
    ],
    "mypy-type-checker.importStrategy": "fromEnvironment",
    "mypy-type-checker.reportingScope": "workspace",
    "mypy-type-checker.preferDaemon": false,
    "mypy-type-checker.showNotifications": "onError",
    "mypy-type-checker.args": [
        "--config-file=${workspaceFolder}/mypy.ini"
    ],
    "python.terminal.activateEnvironment": false,
    "python.defaultInterpreterPath": "${env:VIRTUAL_ENV}"
```

* `python.defaultInterpreterPath` allows us to pickup our `direnv` managed virtual envs
  in each project
  * `mypy-type-checker.importStrategy` then allows using those env based imports
* `mypy-type-checker.args` provides the path to our common mypy config
* `pe-checker.reportingScope` allows us to scan the entire project, and not just the
  currently open file
