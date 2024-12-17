---
title: "Fetching and interacting with GitHub commit status checks"
date: 2024-12-14T00:00:00-00:01
url: "/one-offs/working-with-gh-commit-checks"
Description: |
    Utility function for fetching all checks for a given GitHub commit (e.g for use
    in pipelining functions).
disable_comments: true
type: posts
sidebar_toc: false
categories:
 - one-offs
tags:
 - bash
 - git
---

A


```bash
function get_all_check_statuss(){ local org_repo="${1}" commit="${2}"
    local statuses="$(curl -sS \
        -H "Accept: application/vnd.github+json" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        -H "Authorization: Bearer ${token_here}" \
        "https://api.github.com/${org_repo}/commits/${commit}/status?per_page=250")"

    local rc=0
    for context in ${REQUIRED_CHECKS//,/ }; do
        print_info "Checking commit status for ${context}"

        blurb="$(jq -r -S '.statuses[] | select(.context == "'${context}'")' <<< "${statuses}" )"

        if [[ "${blurb}" == "" ]]; then
            print_err "Commit is missing status check for ${context}"
            rc=1
        else
            # print_info "checking status for ${context}"
            status=$(jq -r ".state" <<< "${blurb}")
            desc=$(jq -r ".description" <<< "${blurb}")
            # print_info "found status ${status} for ${context}"

            if [[ "${status}" == "pending" || "${status}" == "null" ]]; then
                rc=1
                print_err "${context} failed"
            fi
        fi
    done

    return ${rc}
}
```

Usage:

```bash
export REQUIRED_CHECKS=basecontext/check1,basecontext/check2,basecontext/check3,...

get_all_check_statuss my-org/repo1 54dfaer
```
