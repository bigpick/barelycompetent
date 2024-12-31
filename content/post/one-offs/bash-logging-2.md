---
title: "Useful bash utils (part two)"
date: 2024-12-31T00:00:00-00:01
url: "/one-offs/bash-utils"
Description: |
    Additional simple uility functions for working in shell scripts.
type: posts
sidebar_toc: true
categories:
 - one-offs
tags:
 - bash
---

As a follow-up to my original post on [useful bash logging utils](../bash-log-helpers), here
are a few more simple bash utils that I include in all of my scripts.

## Common script layout

By far the most useful pattern I've settled on is a common directory of scripts,
organized similarily to how you would for any other "proper" language: each file
containing a particular scope of utils.

I achieve this by having a `scripts/` dir (which is part of a common git submodule
that all projects inherit, so is leveraged "for free" across any repo in the org),
that has a numerous files in it for the associated utilities.

A subset of the `scripts/` dir might look something like this:

```text
scripts/
    git.sh
    common.sh
    constants.sh
```

These are all still just used as _glue_, but its nice to have a clean set of well
maintained functions for your crazy glue, sometimes :)


### Importing

To be able to leverage code inside these common script files, you structure the shared
scripts such that you can inherit them nicely (usually bundling everything up into
`common.sh`). Then, you can access them by making sure the top of your scripts look
like so:

#### Example 1

To import some constants in `scripts/git.sh` from `scripts/constanst.sh`:

```bash
#!/usr/bin/env bash

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
. "${script_dir}/common"

# ... rest ...
```

#### Example 2

To use some function defined in `scripts/git.sh` in your business logic (where
your business logic script is one directory higher than the `scripts/` dir):

```bash
#!/usr/bin/env bash

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
. "${script_dir}/scripts/common"

# ... rest ...
```

Notice that the only difference is that the path being sourced must be updated based on
the relative location to the scripts directory.

## Utils

### Parsing CLI

This utility function enables passing/parsing CLI args to a script, like

```bash
./some-script.sh --arg=foobar --arg-two=goobar --verbose [--help]
```

Function (assuming `--arg` is required, and `--arg-two` is a CSV list that is split
into an array of items):

```bash
parse_cmd_arguments(){ local args="$@" num_args=$#
    local arg arg_two split_arg_two

    if ((num_args < 1)); then
       usage_help; exit 1
    fi

    for i in "$@"; do
        case $i in
            --arg=*)     arg="${i#*=}";;
            --arg-two=*) arg_two="${i#*=}";;
            --verbose)   VERBOSE=1;;
            --help)      usage_help; exit 0;;
            *)           echo "Unknown arg: ${i#*=}" && usage_help && exit 1;; # unknown option;;
        esac
    done

    [[ $arg == "" ]] && { echo "ERR - must set --arg=\"...\""; usage_help; exit 1; }
    ARG=$arg

    if [[ "${arg_two:-}" != "" ]]; then
        ARG_TWO_VALUES=(${arg_two//,/ })
    fi
}
```

Use it in your entrypoint like so:

```bash
main(){ local cmd_line_pkgs="$@"
    declare VERBOSE ARG ARG_TWO_VALUES
    parse_cmd_arguments "$@"
    # ...
}

main "$@"
```

### Strip whitespace

This utility will remove all leading/trailing whitespace:

```bash
trim() {
    local var="$*"
    # remove leading whitespace characters
    var="${var#"${var%%[![:space:]]*}"}"
    # remove trailing whitespace characters
    var="${var%"${var##*[![:space:]]}"}"
    printf '%s' "$var"
}
```

### Log if failed

This utility function will run a command while capturing its output to a temporary file;
the output will only be shown in the case that the command fails:

```bash
run_cmd() {
    tmp=$(mktemp) || return # this will be the temp file w/ the output

    "$@"  > "$tmp" 2>&1 # this should run the command, respecting all arguments
    ret=$?

    [ "$ret" -eq 0 ] || {
        print_err "'$@' failed; Output below:\n<START>\n$(cat "$tmp")\n<END>"; # if $? (the return of the last run command) is not zero, cat the temp file
    }
    rm -f "$tmp"

    return "$ret" # return the exit status of the command
}
```

### Log only if VERBOSE

This utility will run a command as passed and only output (both STDERR and or STDOUT)
if an envar (`VERBOSE` in this example) is not empty:

```bash
run_cmd(){
    rc=0
    if [[ "${VERBOSE:-}" != "" ]]; then
        "$@" || rc=$?
        return $rc
    else
        "$@" &>/dev/null || rc=$?
        return $rc
    fi
}
```

### Get machine arch

```bash
get-arch(){
    # this is old copy from https://github.com/bevry/dorothy
    local arch
    arch="$(uname -m)"
    if test "$arch" = 'aarch64' -o "$arch" = 'arm64'; then
        echo 'a64' # raspberry pi, apple m1
    elif [[ $arch == x86_64* ]]; then
        if [[ "$(uname -a)" == *ARM64* ]]; then
                echo 'a64' # apple m1 running via `arch -x86_64 /bin/bash -c "uname -m"`
        else
                echo 'x64'
        fi
    elif [[ $arch == i*86 ]]; then
        echo 'x32'
    elif [[ $arch == arm* ]]; then
        echo 'a32'
    elif test "$arch" = 'riscv64'; then
        echo 'r64'
    else
        return 1
    fi
}
```

### Terraform fact

This function takes a terrafrom output path and directory and returns its value:

```bash
get_tf_fact(){ local tf_dir="${1}" path="${2}"
    print_func_banner "${FUNCNAME[0]}"

    pushd ${tf_dir} &>/dev/null

    output=$(jq -r -e ".${path}" <<< "$(terraform output --json)")

    popd &>/dev/null
    echo "${output}"
}
```

### Infinite `wget`

I'm not saying its a good idea, but...

```bash
inf_wget(){ local url=$1
    while true; do
        wget -q --retry-connrefused --waitretry=1 --read-timeout=20 --timeout=15 -t 0 --continue "${url}"
        if [ $? = 0 ]; then break; fi;
        sleep 1s;
    done;
}
```

### Escape JSON

This one is a bit of a cheat, because it uses Python, but I'll include it anyways:

```python
#!/usr/bin/env python3

r"""Escape a JSON string.

USAGE:

    json-escape.py '{"foo":"bar"}'

Output like:

    {\"foo\":\"bar\"}
"""

from argparse import ArgumentParser
from json import dumps


def single_flagless_string(parser: ArgumentParser) -> ArgumentParser:
    """Configure a parser to return a single, unamed string from the command line.

    Args:
        parser (ArgumentParser): The argument parser to configure.
    """
    parser.add_argument("str_arg", metavar="str", type=str)
    return parser


if __name__ == "__main__":
    print(dumps(single_flagless_string(ArgumentParser()).parse_args().str_arg))
```
