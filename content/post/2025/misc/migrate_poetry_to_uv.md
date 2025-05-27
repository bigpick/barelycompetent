---
title: "Migrating from poetry to uv: first impressions"
date: 2025-05-04T00:00:00-00:01
url: "/migrating-poetry-to-uv"
Description: |
    A few notes on the process we followed to transition from how
    we were using poetry to uv.
type: posts
sidebar_toc: true
categories:
 - one-offs
tags:
 - python
 - package-management
---

The latest hot item (Astral's [uv](https://docs.astral.sh/uv/getting-started/installation/))
in the Python ecosystem has been on my radar for some time. I had been
holding off adopting until it was a bit more mature, and was waiting
to see what the community consensus was after some soaking period.

Well, safe to say, looks like `uv` is here to stay - and that I've decided
its finally time to cut our project over from Poetry.

This post will serve as a real quick guide on how we swapped, and any
potential pitfalls we encountered along the way.

>[!IMPORTANT] Heads up!
> For this guide, we will be walking through converting our
> [plox-pytools](https://github.com/codeplox-dev/plox-pytools) package.

## Steps

### Get uv tooling

Follow [uv's documentation](https://docs.astral.sh/uv/getting-started/installation);
I am doing so on mac, so will use brew:

```bash
brew install uv
```

This gives us `uv` and `uvx`:

```bash
λ  uv --version
uv 0.7.2 (Homebrew 2025-04-30)

λ  uvx --version
uvx 0.7.2 (Homebrew 2025-04-30)
```

### Translate pyproject.toml

Poetry requires a slightly different format `pyproject.toml` file than
what `uv` expects, so we need to convert our existing file to be in
line with what is required. You can do this manually, but I wanted to
try out some available migration tools, namely,
[`migrate-to-uv`](https://github.com/mkniewallner/migrate-to-uv).

This utility is available automatically to `uvx`, so we can simply run
from the root of our repo like so:

```bash
uvx migrate-to-uv
```

#### Problems

Running the above resulted in:

```text
...
thread 'main' panicked at src/converters/poetry/project.rs:27:57:
called `Option::unwrap()` on a `None` value
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
```

Not a useful error message. Enabling the full trace yielded the
following:

```bash
RUST_BACKTRACE=1 uvx migrate-to-uv

thread 'main' panicked at src/converters/poetry/project.rs:27:57:
called `Option::unwrap()` on a `None` value
stack backtrace:
   0: _rust_begin_unwind
   1: core::panicking::panic_fmt
   2: core::panicking::panic
   3: core::option::unwrap_failed
   4: migrate_to_uv::converters::poetry::project::get_authors
   5: <migrate_to_uv::converters::poetry::Poetry as migrate_to_uv::converters::Converter>::build_uv_pyproject
   6: migrate_to_uv::converters::Converter::convert_to_uv
   7: migrate_to_uv::main
   8: migrate_to_uv::main
note: Some details are omitted, run with `RUST_BACKTRACE=full` for a verbose backtrace.
```

For some reason there looks to be something wrong with the authors
list in the `pyproject.toml`:

```toml
[tool.poetry]
authors = ["bigpick <bigpick@codeplox.dev>"]
# ...
```

I changed it such that all the deprecated options from the
[`tool.poetry`](https://python-poetry.org/docs/pyproject/#the-project-section)
legacy section were moved to the top level `project` key, like so:

```toml
authors = [{ name = "bigpick",  email = "bigpick@codeplox.dev"}]
# ...

[tool.poetry]
# ...
```

Running

```bash
uvx migrate-to-uv --dry-run
```

Now successfully completes.

Finally:

```bash
uvx migrate-to-uv
Locking dependencies with "uv lock"...
Using CPython 3.12.9 interpreter at: <path>
Resolved 64 packages in 1.28s
Successfully migrated project from Poetry to uv!
```

We see that it has:

1. Created a `uv.lock`
1. Removed the `poetry.lock`
1. Updated the `pyproject.toml` file

### Updating our .envrc

A bit of an anti-pattern, perhaps, but we had historically used
[direnv](https://github.com/direnv/direnv) to manage both the Python
version and venv (and not poetry itself).

An example `.envrc` for us looked like the following:

```bash
export PY_VERS=3.12.9
export SUPPORTED_PY_VERS="python3.12 python3.11 python3.13 python3.10 python3.9"

print_err(){
    printf "+++ ERROR +++ %s\n" "$*" >&2;
}

print_warn(){
    printf "+++ WARNING +++ %s\n" "$*" >&2;
}

get_candidate_py_vers(){
    PY_VERS_NO_PATCH=$(cut -d. -f1-2 <<< "${PY_VERS}")
    for py in python${PY_VERS_NO_PATCH} python3 python; do
        if command -v ${py} >/dev/null 2>&1 ; then
            # Check if it matches desired
            py_vers=$(awk '{print $2}' <<< "$(${py} -V)")
            if [[ "${py_vers}" == "${PY_VERS}" ]]; then
                # found exact match
                echo "$py"
                return
            fi
        fi
    done

    print_warn "Did not find exact match for desired ${PY_VERS}, falling back to major.minor compat"

    # python, python3, pythonX.YY either not installed or don't match exact PY_VERS,
    # fallback to trying to match just major.minor
    for py in $(echo $SUPPORTED_PY_VERS) python3 python; do
        py_vers=""
        py_vers_patchless=""
        if command -v ${py} >/dev/null 2>&1 ; then
            py_vers=$(awk '{print $2}' <<< "$(${py} -V)")
            py_vers_patchless=$(cut -d. -f1-2 <<< "${py_vers}")

            if [[ "${SUPPORTED_PY_VERS}" == *"python${py_vers_patchless}"* ]]; then
                # found supported major.minor, exit early
                # n.b. - prioritizes order versioning left to right in SUPPORTED_PY_VERS
                echo "$py"
                return
            fi
        fi
    done

    print_err "Did not detect python or python3 installed! Please install one of Python's '${SUPPORTED_PY_VERS}' (ideally $PY_VERS) and try again!"
    exit 1
}

if [[ "$(which pyenv)" == "" ]]; then
    layout python "$(get_candidate_py_vers)"
else
    layout pyenv "${PY_VERS}"
fi
```

That would attempt to use Python 3.12.9 as the version of Python to create
the venv with. If `pyenv` was present, it would leverage that to
make the env and then that is all.

If not, it would default to more relaxed checks of just python3.12,
then 3.11, then ... (all versions in the `SUPPORTED_PY_VERS` in the
order they are defined in that variable). This way,
if you had at least _some_ form of supported python MAJOR.MINOR installed,
it would leverage that. Problem is, it still wouldn't install anything
if you didn't, so if you didn't have `pyenv` _or_ a supported MAJOR.MINOR
Python version, it'd error out.

Turns out, having `uv` and `direnv` is a pretty hot topic:

* <https://github.com/direnv/direnv/wiki/Python#uv>
* <https://github.com/direnv/direnv/issues/1250>
* <https://github.com/direnv/direnv/pull/1352>
* <https://github.com/direnv/direnv/issues/1338>
* <https://github.com/direnv/direnv/pull/1329>
* <https://github.com/direnv/direnv/issues/1264>
* ... and so on ...


For now, it seems you have to manually add support for `layout uv`
by following the commands in the wiki (first bullet).

After doing so, we run

```bash
echo "3.12.9" > .python-version
direnv block .
rm -rf .direnv
direnv allow .
```

And notice our newly created `venv`, managed by direnv+uv:

```bash
direnv allow .
# direnv: loading <path>/plox-tools/.envrc
# direnv: No virtual environment exists. Executing `uv venv` to create one.
# Using CPython 3.12.9 interpreter at: <path>/bin/python3.12
# Creating virtual environment at: .venv
# Activate with: source .venv/bin/activate

which python
```

Shows the venv python.

#### Problems

1. We no longer have the ability to leverage multiple fallback versions
   nicely, since the `.python-version` file takes a single version.

   This is fine because `uv` will automatically download that version
   if it doesn't exist, so we can be sure that just having the one will
   be OK.

   We will still very much want to test against multiple versions, to
   ensure compatability with multiple Python MAJOR.MINOR versions, but
   that will occur separately from the main projects version.

   Alternatively, `uv` supports a `.python-versions` if you wanted to
   require downloading _multiple_ versions, but thats overkill.

2. I noticed that once this venv is created, if we update the `.python-version`
   file to a different python version, the management of the environment
   breaks down.

To solve this, it turns out I can leverage an undocumented, existing
internal feature of direnv: the `watch_file` syntax. By adding this
to our `.envrc`, any modification to this file will re-trigger the
direnv env to reload, as if you had edited the `.envrc`!

As it turns out, a lot of this work has already been considered:

* <https://github.com/direnv/direnv/pull/1352>

This is what I settled on:

```bash
layout_uv() {
  # Watch the uv configuration file for changes
  watch_file .python-version pyproject.toml uv.lock

  # Use --frozen so that direnv entry does not change the lock contents. This
  # can fail if the lock file is badly out of sync, but it'll report that to the
  # user and the resolution is obvious.
  uv sync --frozen &>/dev/null || echo "Bad uv.lock state; Be sure to run 'uv sync!'"
  direnv_load uv run --no-sync direnv dump
}
```

This makes it so that when the case that the `.python-version` file is
updated and direnv is reloaded, if there is an existing venv, it will
detect that it is not the appropriate version (must match to MAJOR.MINOR.PATCH)
and delete and re-create the venv.

Users still need to manuall `uv sync --all-groups` after the direnv
env is sourced, but I am fine with that because otherwise it would mean
enabling direnv to do it on every change or entry.

Stay tuned for the next post walking through updating our build scripts
and Makefile entrypoints accordingly!
