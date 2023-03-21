---
title: "The GitHub contribution chart is a lie."
date: 2023-03-20T01:24:55-05:00
url: "/meta/stop-judging-github-contrib-graphs"
Description: |
    "What's stopping your GitHub profile from looking like this?"
    Uh, actually preserving a sane history of commits on my repository's
    default branch? Having only succesfully built commits on the main
    repo branch? Should I go on?
type: posts
categories:
 - meta
---

## Background

This post is about a year behind the trend at this point, but if you
were a developer and happened to be browsing `r/ProgrammerHumor`, or
maybe follow some developer-geared Twitter accounts, you probably noticed
quite a few "What's stopping you from coding like this?" posts. It's a
trend making (mostly) satire of why you don't develop in some (usually)
strange or esoteric way that wouldn't be plausible physically, literally,
or in any sense.

A subdivision of this is the set of posts dealing with absurd
contribution graphs, displaying hundreds to thousands of commits over
many consecutive days over the course of (at least) a year. Most of the
time, it's just to show off some app that someone wrote or
used to make their contribution graph look like pacman or spell out a
word or something else.

But, humor me, let us consider the case where someone seriously values
the contribution graph as a judge of work or activity or other important
metric (maybe your boss, maybe a recruiter, could be anyone, really).

My problem lies with how GitHub determines what commits get bubbled
up onto your contribution graph.

## Not all commits are equal

[According to GitHub][]:

> Commits will appear on your contributions graph if they meet all of the following conditions:
>
> * The email address used for the commits is associated with your account on GitHub.com.
> * The commits were made in a standalone repository, not a fork.
> * The commits were made:
>    * In the repository's default branch
>    * In the gh-pages branch (for repositories with project sites)

The first two bullets are fairly obvious. However, the last bullet is
were my contention lies. Particularly:

> **In the repository's default branch**

In other words: If you squash your PR merge commits, you lose!

You can imagine my suprise one day when, after I had made dozens of
commits as part of a Pull Request, I finally was satisfied with the
changes, tests were passing, and I clicked "Squash and merge".

Going to check my profile for the sweet, sweet little neon green square
for the day, I was confused when I saw the ugly little dark green box
in its place.

Sure enough, hovering over the box showed two contributions for the day:

* One for opening the Pull Request
* A second as a result of the merge commit of the PR into the default
  branch of the target repo.

As far as the GitHub contribution graph is concerned, that was just a
single commit. Sure, one could go into the repository's history via
`git` commands and see the squashed commits and co-authors. But I highly
doubt a recruiter or someone naively glancing through your GitHub profile
would care to do so.

## Testing non-squashed merges

Personally - I only use "squash and merge" as a means for merging pull
requests. I prefer the cleaner approach it provides, especially when
working with many people on a project (where at least a handful have
very little concept of "good" git flow).

BUT, for the sake of this post, let us try and see what happens if
we _don't_ squash when merging the pull request.

Let's create a branch with some commits on it:

```bash
git clone git@github.com:bigpick/test-repo-for-commit-counting.git

cd test-repo-for-commit-counting

git checkout -b non-squashy-boi

for i in {1..20}; do
    git commit --allow-empty -m "chore: Empty commit to pad contribution graph."
done

git push -u origin non-squashy-boi
```

Then head on over to the repo and create a PR:

* https://github.com/bigpick/test-repo-for-commit-counting/pull/1

Click on "Merge" (**No squash**), and poof! We now have a default branch
with 22 commits on it (1 for repo creation, 20 for the feature branch,
1 for the merge commit).

Heading on over to my profile's contribution graph:

{{< image src="/img/2023/meta/git-contribs/graph.png" alt="updated_git_contrib_graph.png" position="center" style="border-radius: 8px;" >}}

Would you look at that, all the commits are now counted.

## Related

* https://github.com/isaacs/github/issues/1303

## Solutions

Off the top of my head:

* Ignore the GitHub contribution graph, or at least, view it as a dashboard
  for easily seeing other stats, **not** as a dashboard displaying any
  stats _itself_.
* Don't use squash and merge
* Get GitHub to remove the contribution graph.
* "Teach" the contribution graph to be able to parse commits out of a
  squashed commit, and attribute each commit individually

Personally, I'm going to continue to use Squash and merge, and remember
to pay less attention to people's contribution graphs.

[According to GitHub]: <https://docs.github.com/en/account-and-profile/setting-up-and-managing-your-github-profile/managing-contribution-settings-on-your-profile/why-are-my-contributions-not-showing-up-on-my-profile#contributions-that-are-counted>
