---
title: "Mutable default arguments in Python are bad"
date: 2023-04-16T01:24:55-05:00
url: "/python/mutable-default-arguments-in-Python-are-bad"
Description: |
    Using a mutable default argument in Python is a bad idea. When in
    doubt, use None.
type: posts
categories:
 - programming
tags:
 - python
---

## Background

Python allows defining default arguments as part of a function definition:

```python
def greet(name: str = "world"):
    print(f"Hello, {name}!")
```

### Info

The above can be called without any arguments, and it will stub in `world` as if
it was passed as the argument:

```python
>>> def greet(name: str = "world"):
...     print(f"Hello, {name}!")
...
>>> greet()
Hello, world!
```

### Immutable arguments

This is all fine and well, since `str` is immutable, we cannot modify the
argument across calls:

```
>>> def greet(name: str = "world"):
...   print(f"Hello, {name}!")
...   name += "!"
...

>>> greet()
Hello, world!

>>> greet()
Hello, world!
```

Similarly, this is true for all immutable types:

- numbers

  ```python
  >>> def greet(num: int = 42):
  ...   print(f"Hello, {num}")
  ...   num += 1
  ...
  >>> greet()
  Hello, 42

  >>> greet()
  Hello, 42
  ```

- bools

  ```python
  >>> def greet(truthy: bool = False):
  ...   print(f"Value: {truthy}")
  ...   truthy = True
  ...
  >>> greet()
  Value: False

  >>> greet()
  Value: False
  ```

- strings
- bytes

  ```python
  >>> def greet(name: bytes = b"world"):
  ...   print(f"Hello, {name.decode()}")
  ...   name += b"!"
  ...
  >>> greet()
  Hello, world

  >>> greet()
  Hello, world
  ```

- tuples

  ```python
  >>> def greet(names: tuple[str, str] = ("foo", "bar")):
  ...   print(f"Hello, {names[0]} and {names[1]}")
  ...   names = ("baz", "qux")
  ...
  >>> greet()
  Hello, foo and bar

  >>> greet()
  Hello, foo and bar
  ```

### Mutable types

The problem arises when a _mutable_ type is specified as an argument, which has
a default value:

- lists

  ```python
  >>> def greet(names: list[str] = ["foo"]):
  ...     for name in names:
  ...         print(f"Hello, {name}!")
  ...     names.append("goo")
  ...
  >>> greet()
  Hello, foo!

  >>> greet()
  Hello, foo!
  Hello, goo!

  >>> greet()
  Hello, foo!
  Hello, goo!
  Hello, goo!

  >>> greet()
  Hello, foo!
  Hello, goo!
  Hello, goo!
  Hello, goo!
  ```

- dicts

  ```python
  >>> def greet(names: dict[str, str] = {"foo": "bar"}):
  ...     for person, greeting in names.items():
  ...         print(f"{person} says {greeting}")
  ...     names["baz"] = "qux"
  ...
  >>> greet()
  foo says bar

  >>> greet()
  foo says bar
  baz says qux
  ```

- sets

  ```python
  >>> def greet(names: set[str] = {"world"}):
  ...     for name in names:
  ...         print(f"Hello, {name}")
  ...     names.add("goo")
  ...
  >>> greet()
  Hello, world

  >>> greet()
  Hello, goo
  Hello, world
  ```

### Solution

Sometimes, modifying a mutable type is desired. In such cases, the examples
above would be a good thing.

However, where problems arise is when you use a mutable type but are trying to
model an "uninitialized" state.

For example, if you want to have the default argument for the function be an
empty list, in the case that a user doesn't pass any values to it, you'd think
that giving the method a `[]` as default value would be fine.

You run the function, its works, but later in the program, it now is failing or
throwing wrong/duplicate data. This is because prior state is getting stored in
that argument.

> Python's default arguments are evaluated only once when the function is
> defined, not each time the function is called. This means that if a mutable
> default argument is used and is mutated, it is mutated for all future calls to
> the function as well.

If you wish to instead have an uninitialized value for a default argument of a
mutable type, you should opt for using `None` and checking accordingly:

```python
def greet(names: Optional[listr[str]] = None):
    if not names:
        return

    # do stuff ...
```

As seen in the above, Python type hinting fully supports a "maybe" type, via the
`Optional` type.

Be sure to be on the lookout next time you want to use mutable arguments and
default values.
