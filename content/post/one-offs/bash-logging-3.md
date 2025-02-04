---
title: "Running \"log if failed\" with \"set -e\""
date: 2025-01-11T00:00:00-00:01
url: "/one-offs/bash-utils-3"
Description: |
    Following up with some additional input for the "log if failed"
    bash logging utility.
type: posts
sidebar_toc: true
categories:
 - one-offs
tags:
 - bash
---

As a follow-up to my second post on [useful bash logging utils](../bash-utils), here
I wanted to expand a bit more on a particular helper function that I use
as part of my "bash logging toolkit".

## Original

Last time, I had shown this function:

> **Log if failed**
>
> This utility function will run a command while capturing its output to a temporary file; the output will only be shown in the case that the command fails:
>
> ```bash { linenos=true }
> run_cmd() {
>     tmp=$(mktemp) || return # this will be the temp file w/ the output
>
>     "$@"  > "$tmp" 2>&1 # this should run the command, respecting all arguments
>     ret=$?
>
>     [ "$ret" -eq 0 ] || {
>         print_err "'$@' failed; Output below:\n<START>\n$(cat "$tmp")\n<END>"; # if $? (the return of the last run command) is not zero, cat the temp file
>     }
>     rm -f "$tmp"
>
>     return "$ret" # return the exit status of the command
> }
> ```

This won't always work as intended, especially if you are leveraging,
say, [bash strict mode](http://redsymbol.net/articles/unofficial-bash-strict-mode/),
particularly, when using `set -e`.

This is because on line 4 when we execute the command,

> `"$@"  > "$tmp" 2>&1`

if an error occurs there, the executing script will immediately exit,
without having a chance to properly handle the command as intended.

To resolve this, we'd be better off catching an error at this point.

## Updated "log if failed"

```bash { linenos=true }
run_cmd() {
    tmp=$(mktemp) || return 1 # this will be the temp file w/ the output

    ret=0
    "$@"  > "${tmp}" 2>&1 || ret=$? # this should run the command, respecting all arguments

    [ "$ret" -eq 0 ] || {
        print_err "'$@' failed; Output below:\n<START>\n$(cat "${tmp}")\n<END>"; # if $? (the return of the last run command) is not zero, cat the temp file
    }
    rm -f "${tmp}"

    return "${ret}" # return the exit status of the command
}
```

By declaring `ret=0` initially, we set the error check value to a known
"good" state. The only time it will be set to something bad is if the
execution of the command doesn't exist successfully, in which case
we now catch and store back into `ret`. This time, though, because we
handle the potential failure, we can actually get to the "logging" of the
failed command and then properly cleanup and exit accordingly.

We also are adding a non-zero exit code if we can't properly `mktemp`
to start the utility, as well.

As a follow up, I'll look to add a "dryrun" and "trace" operation mode,
so that we can have the ability to get additional insight and control
into the execution of the utility as well.
