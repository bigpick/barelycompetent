---
title: "Simple Python timer contextmanager"
date: 2024-12-16T00:00:00-00:01
url: "/one-offs/simple-python-timer-contextmanager"
Description: |
    Python module for executing a set of commands under a timer contextmanager.
type: posts
sidebar_toc: false
categories:
 - one-offs
tags:
 - python
---

Save the following to a `.../timing.py`:

```python
from __future__ import annotations

from collections.abc import Generator, Mapping
from contextlib import contextmanager
from functools import wraps
from time import time
from typing import Any, Callable, Optional


class TimingRecord:
    def __init__(self, fn_name: str):
        """Create a new ``TimingRecord`` instance."""
        self.fn_name = fn_name

        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None
        self.elapsed_time: Optional[float] = None

    def start(self) -> TimingRecord:
        """Start the record's capturing time."""
        self.bail_if_finished()

        self.start_time = time()

        return self

    def finish(self) -> TimingRecord:
        """Stop and record the record's capturing time."""
        self.bail_if_finished()

        if not self.start_time:
            raise RuntimeError("TimingRecord finished but never started")

        self.end_time = time()
        self.elapsed_time = self.end_time - self.start_time

        return self

    @property
    def report(self) -> Mapping[str, Any]:
        """Summarize the time spent and return as a dict report."""
        return {
            "fn_name": self.fn_name,
            "time": f"{self.elapsed_time:2.6} seconds",
            "time_s": self.elapsed_time,
        }

    def bail_if_finished(self) -> None:
        """Crash if a record is attempted to be modified after it has been ended already."""
        if self.end_time is not None:
            raise RuntimeError("Attempt to modify after finished")


def timed(fn: Callable[[Any], Any]) -> Callable[[Any], Any]:
    """Wrap a function to be timed for execution."""
    record = TimingRecord(fn.__name__)

    @wraps(fn)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        record.start()

        try:
            result = fn(*args, **kwargs)
        finally:
            record.finish()

        return result, record.report

    return wrapped


@contextmanager
def timer(fn_name: str) -> Generator[TimingRecord, None, None]:
    """Context manager wrap a timer to execute a function."""
    timing_record = TimingRecord(fn_name)
    try:
        timing_record.start()
        yield timing_record
    finally:
        timing_record.finish()
```

Usage:

```python
from timing import timer
from time import sleep

def fast_command():
    print("Hello, fast!")

def medium_command():
    sleep(3)
    print("Hello, medium!")

def slow_command():
    sleep(10):
    print("Hello, slow!")
```

Results:

```python
with timer("fast_command") as t:
    fast_command()

print(t.report)
# Hello, fast!
# {'fn_name': 'fast_command', 'time': '4.41074e-05 seconds', 'time_s': 4.410743713378906e-05}
```

```python
with timer("medium_command") as t:
    medium_command()

print(t.report)
# Hello, medium!
# {'fn_name': 'medium_command', 'time': '3.00073 seconds', 'time_s': 3.0007288455963135}
```

```python
with timer("slow_command") as t:
    slow_command()

print(t.report)
# Hello, slow!
# {'fn_name': 'slow_command', 'time': '10.0044 seconds', 'time_s': 10.004425048828125}
```

Altenatively, without the context manager:

```python
t = timed(medium_command)
output, exec_time = t()
# Hello, medium!
output
# <nothing, bc medium_command doesn't return anything>
exec_time
# {'fn_name': 'medium_command', 'time': '3.00208 seconds', 'time_s': 3.0020811557769775}
```
