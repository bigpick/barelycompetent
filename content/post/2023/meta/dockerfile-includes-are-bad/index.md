---
title: "DON'T use C++ preprocessing to keep your Dockerfiles DRY."
date: 2023-03-30T01:24:55-05:00
url: "/meta/dont-try-to-include-dockerfiles"
Description: |
    Last week I wrote about how it is 2023 and there is still no way to
    officially include a dockerfile as part of another one. Despite
    ultimately providing a means of doing so, this article argues the
    opposite - and only a week later!
type: posts
categories:
 - docker
---

{{< image src="/img/2023/meta/dont-do-dockerfile-includes/ilied.jpg" alt="A photo of the 'So that was a fucking lie' meme of Tyler the Creator" position="center" style="border-radius: 8px;" >}}

## Background

Last week I wrote about
[how you can sanely import a dockerfile despite still not being supported in 2023](/meta/how-to-include-dockerfiles/).

In that article, I talked about how asinine it is that a feature so simple is
still not supported despite having an issue for it for over 10 years, along with
other complaints.

Ultimately I ended up stating I think the workaround was worth it.

I am now here but a week later saying: _so that was a lie_.

## Why

### Support

The ability to extend a given dockerfile using includes is maybe nice if
you are only ever working on your own projects. However, the benefits of
such power stop about there.

Consider the case where a set of dockerfiles are being used by a group
of many people, say in a corporate organization. These individuals are
from different teams, but working towards the same goal. They share an
approach of doing things (i.e a consistent approach leveraging Docker).

As such, when things go wrong, one person will often look for the help
of others, hoping to gain insight from their prior experience. However,
when someone inevitably asks "where's your dockerfile" and they give you
a file with 10 include statements - that person is no longer interested
in helping.

Sure, you could render the dockerfile locally first, and then give them
that. But a side effect of the C++ preprocessing work was that the end
result Dockerfile looks like absolute hot garbage thanks to the lack
of formatting, comments, and weird whitespacing and wrapping. It also
then adds additional burden to the individual seeking help, because now
they need to do this everytime they want to be able to send the file out
to somewhere that doesn't have intimate knowledge of their import chain.

### Explicitness in Tracking

By storing the dockerfiles in GitHub, one has the ability to go back at
any revision and see at a point in time what that file consisted of.

Say, an auditor wants to know what contents were in your pod that was
deployed in production at one date. They ask for the dockerfile, to
examine the contents. If you give them a 10 line file that is just all
include statements, you're going to have a bad audit experience:)

Now, if someone wants to know the contents and are only going to be
doing so from a visual perspective (and checking out the contents at
that time and then rendering it is out of the question) it is now a huge
burden to look at 10 tabs worth of files.

Sure, you could upload the generated file alongside the other ones, but
that would require additional work that wouldn't be natural to the
development flow - and all the problems with how the C++ preprocessing
formats still exist.

### New adopters

If a new developer is assigned with working with your project and tasked
with getting up to speed on it, you can bet that if they had one single
file to learn instead of N spread across all sorts of directories,
they'll be much more usefull.
