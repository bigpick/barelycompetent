---
title: "Remove gitsubmodule from project"
date: 2024-12-11T00:00:00-00:01
url: "/one-offs/remove-git-submodule"
Description: |
    Utility function for effectively removing a git submodule from a project.
disable_comments: true
type: posts
sidebar_toc: false
categories:
 - one-offs
tags:
 - bash
 - git
---


```bash
function rm_submodule(){ local submodule="${1}"
    git submodule deinit -f "${submodule}"
    git rm "${submodule}"
    git commit -m "chore: remove ${submodule}"
    rm -rf .git/modules/"${submodule}"
```

Usage:

```bash
rm_submodule my-submodule && git push
```
