---
title: "Use C++ preprocessing to keep your Dockerfiles DRY."
date: 2023-03-22T01:24:55-05:00
url: "/meta/how-to-include-dockerfiles"
Description: |
    It is now 2023 and Docker still does not formally support some
    form of "INCLUDE" statement. Anyone who wishes to leverage such
    features natively must look elsewhere (e.g Podman). However,
    presented below is a way to achieve the same end-result, will still
    sticking with Docker (Bonus: No inclusion of random 3rd party
    software!)
type: posts
categories:
 - meta
---

{{< image src="/img/2023/meta/dockerfile-includes/meme.png" alt="A photo of the One Does not simply meme with the caption 'one does not simply include dockerfile'" position="center" style="border-radius: 8px;" >}}

## Background

The infamous:

> [Proposal: Dockerfile add INCLUDE](https://github.com/moby/moby/issues/735)

An issue opened in **May of 2013**. That is now almost **10 years ago
at this point**!!. And Docker _still_ does not provide a way to achieve
this result natively!

Go read that issue thread, and the web of linked PRs and issues
associated. I think its safe to say this feature will _never_ come to
Docker.

## Alternatives

### Podman

Podman implemented this capability in buildah in mid 2018; See [here][]
for the discussion.

Switching to podman/buildah is one option.

The other, which is what I use, is to just leverage what buildah does
in your files directly. That is, manually invoking the C++ preprocessor
to build the `Dockerfile` yourself.

### edrevo's dockerfile-plus

Reference: https://github.com/edrevo/dockerfile-plus#include.

If you want to use a 3rd party set code that's been left unmaintained
for multiple years at this point, well, who am I to tell you how to live your
life. Personally, I don't consider this an option at all.

### Rolling your own

A trivial use case, to demonstrate:

1. Multiple `.dockerfile` stubs that you wish to include to your image's
  build file:

   * `ubu_2204_base.dockerfile`:

        ```dockerfile
        FROM ubuntu:22.04

        RUN apt-get -y update
        RUN apt-get -u upgrade
        ```
   * `direnv.dockerfile`:

        ```dockerfile
        COPY --chown=root:root direnv.linux-amd64 /root/bin/direnv
        RUN echo 'eval "$(direnv hook bash)"' >>  /root/.bashrc
        ENV PATH="/root/bin:$PATH"
        ```
   * `kubectl.dockerfile`:

        ```dockerfile
        RUN curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
        RUN chmod +x ./kubectl
        RUN mv kubectl /usr/local/bin
        ```

2. A template file that will be used to build our end-state `Dockerfile`:

    ```dockerfile
    #include "ubu_2204_base.dockerfile"
    #include "direnv.dockerfile"
    #include "kubectl.dockerfile"
    ```

3. Command to generate our `Dockerfile`:

    ```bash
    cpp -E -P Dockerfile.in > Dockerfile
    ```

Inspecting the created `Dockerfile`:

```dockerfile
FROM ubuntu:22.04
RUN apt-get -y update
RUN apt-get -u upgrade
COPY --chown=root:root direnv. 1 -amd64 /root/bin/direnv
RUN echo 'eval "$(direnv hook bash)"' >> /root/.bashrc
ENV PATH="/root/bin:$PATH"
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
RUN chmod +x ./kubectl
RUN mv kubectl /usr/local/bin
```

## Is it worth it?

The answer to this question depends on your situation. For example,
anything that will mess with the CPP preprocessing is no longer able
to be leveraged in your Dockerfile stubs (e.g: you can no longer use
comments in your Dockerfiles). The possibility of other foot-guns exist,
too.

The generated Dockerfile is also pretty dense/hard to read, since each
file is jammed right up against each other - there's no way to preserve
sane whitespacing, or comments, and mutli-line lines from stubs get
squashed into very long, single lines. I don't consider this too big
a problem, since I think using the generated Dockerfile for anything
other than stuffing to the build command is using this proccess
sub-optimally.

However, there _is_ the argument that you now lose the ability to track
a single, checked-in version of the file that will be used to build the
container, which I think is a very valid argument. Requiring an outsider
to now look at each individual stub file to see what is all available
to the build is not great.

Even with the above, I think there's a time and place to leverage the
capability. Add in a Makefile target, and have your `make` process
automatically generate the file on the flow, and before you know it,
you'll have a way to make patterned containers without repeating
many lines of code.

What do you think?

[here]: <https://github.com/containers/buildah/issues/851>
