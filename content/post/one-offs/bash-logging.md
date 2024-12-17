---
title: "Useful bash logging helpers"
date: 2024-12-17T00:00:00-00:01
url: "/one-offs/bash-log-helpers"
Description: |
    Simple uility functions for logging information to STDERR when working with shell.
type: posts
sidebar_toc: false
categories:
 - one-offs
tags:
 - bash
---

I like to log to STDERR so that when working with command output you don't have to
worry about capturing information/debug information when executing
a command and trying to store its "actual" output.

Here are some simple function I use a lot when writing Bash/Shell scripting (e.g in
pipeline scripts) that does that effectively:

```bash
###
# Print a message with an info prefix to stderr.
###
print_info(){
    printf "+++ INFO +++ %s\n" "$*" >&2;
}

###
# Print a message with an error prefix to stderr.
###
print_err(){
    printf "+++ ERROR +++ %s\n" "$*" >&2;
}

###
# Print a banner message to stderr.
###
print_func_banner(){ local funcname="${1}"
    printf "============================ Inside: %s ============================\n" "${funcname}" >&2;
}
```

Usage:

```bash
print_info "Some informational text"
# +++ INFO +++ Some informational text
```

```bash
print_err "Something bad"
# +++ ERROR +++ Something bad
```

```bash
function foo(){
    print_func_banner "${FUNCNAME[0]}"

    echo "Hello, world!"
}

output=$(foo)
echo "Output is: '$output'"
# ============================ Inside: foo ============================
# Output is: 'Hello, world!'

```
