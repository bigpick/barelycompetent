---
title: "Exploring docker buildx bake"
date: 2024-12-29T01:24:55-05:00
url: "/misc/exploring-docker-buildx-bake"
Description: |
    Exploring the capabilities possible provided by the expiremental `bake`
    option provided as part of `docker buildx`.
type: posts
sidebar_toc: true
categories:
 - docker
tags:
 - docker
 - containers
---

## tl;dr

Use [`docker buildx bake`](https://github.com/docker/buildx/blob/master/docs/reference/buildx_bake.md) to define a high-level build file to control the building/interweaving of multiple images.

* No additional dependency on `docker compose`
* No requirement on invoking `docker build` mutltiple times for each `--target ...` stage
* DRY as possible

## Background

A lot of my time the past year was centered around designing and implementing our team's common approach to CI/CD. As part of this, we were forced into numerous pieces of tech and certain implementations and options, etc. One of which was that all our containers had to be Ubuntu. As part of this, I took it upon myself to build a common container, which gets nightly updates, builds, and publication via our internal CI/CD system. This "base image" is the foundational image we use to run _all_ projects in CI/CD. As well as acting as the common/shared "development environment" for our projects, this container _also_ serves other functions, notably: it builds from source our set of projects' currently required/maintained Python versions.

### Missing "slim" Ubuntu Python
One tricky thing that I quickly found out was that there wasn't any really nice official "slim" Ubuntu based Python 3.X images on any sort of public docker registry that I could use (One could argue that if you truly want _slim_ images, then inheriting off an Ubuntu image is not the right choice to begin with, and I'd agree, but I digress...) So, that quickly turned into a requirement: we need to build/maintain our own "slim" Python containers built on a common Ubuntu container image.

## Initial approach

I had taken a somewhat simple approach to solve this requirement:
 A single `Dockerfile` whose contents, among all of our other shared dependencies/etc, was responsible for fetching and building the required Python versions from scratch.

It is a bit more convoluted than that, because we have to fetch Python versions from internally tracked/maintained binaries and whatnot, but that was essentially the gist of it.

Every project, regardless of type, would then inherit off this "base image" for its build stage, and then use a "clean" Ubuntu image (of the same OS/version) for its final, output runner stage that would copy any required bits from the prior build stage that was able to be completed thanks to the big, shared dev env image's contents.

### Dockerfile snippet

I defined `ARG`s so that the invoking process can sometimes override, but essentially, an example of it would look something like so;

> **Note**:
>
> The following assumes that Python 3.11.x should be the default Python
> version in the shared build container; Whichever version is desired
> (if any) just needs to be the only one _not_ `altinstall`'ed.


```dockerfile
ARG UBU_VERS=ubuntu:noble-20241118.1
ARG PY_311_VERS=3.11.11 # etc...
ARG PY_312_VERS=3.12.8
ARG PY_313_VERS=3.13.1

FROM ${UBU_VERS} as builder

# ... other stuff ...

# Download Python tgz's
COPY py-tgz-fetch .
RUN ./py-tgz-fetch ${PY_311_VERS} && \
    ./py-tgz-fetch ${PY_312_VERS} && \
    ./py-tgz-fetch ${PY_313_VERS} && \
    rm py-tgz-fetch

RUN apt-get install -yq <Python build deps> && \
    curl -sSL https://bootstrap.pypa.io/get-pip.py -o get-pip.py && \
    # Install Python 3.13.x; this is as how they describe it in
    # their docs; Note: We 'altinstall' bc we have multiple
    # versions installed, and don't want this as the default
    tar zxf Python-${PY_313_VERS}.tgz -C /usr/local/src && \
    pushd $PWD && cd /usr/local/src/Python-${PY_313_VERS} && \
    echo "Configuring python ${PY_313_VERS}" && \
    ./configure --quiet &>/dev/null && \
    make -j &>/dev/null && make altinstall --quiet &>/dev/null && popd && \
    python3.13 get-pip.py && rm -rf /usr/local/src/Python* && \
    #
    # ... repeat for 3.12.x ....
    #
    # ... repeat for 3.9.x, etc, for all required non-default versions ....
    #
    tar zxf Python-${PY_311_VERS}.tgz -C /usr/local/src && \
    pushd $PWD && cd /usr/local/src/Python-${PY_311_VERS} && \
    echo "Configuring python ${PY_311_VERS}" && \
    ./configure --quiet &>/dev/null && \
    make -j &>/dev/null && make install --quiet &>/dev/null && popd && \
    python3.11 get-pip.py && rm -rf /usr/local/src/Python* && \
    ln -sf /usr/local/bin/python3.11 /usr/local/bin/python && \
    ln -sf /usr/local/bin/python3.11 /usr/local/bin/python3 && \
    apt-get autoremove --purge <Python build deps>
```

At this point, you would now have all versions of Python installed in the common builder image, with the last specified version as the default `python`/`python3` version.

#### py-tgz-fetch

An example, if you were pulling from publically released tgzs:

```bash
#!/usr/bin/env bash

set -euo pipefail

fetch_py_tgz(){ local vers="${1}"
    local url="https://www.python.org/ftp/python/${vers}/Python-${vers}.tgz"

command -v wget &>/dev/null || {
        echo "Please install 'wget'";
        exit 1;
    }

    rm "Python-${vers}.tgz" &>/dev/null || true

    run_cmd wget "${url}" || {
        echo "Could not fetch Python? 'wget ${url}' failed";
        exit 2;
    }
}


[[ "${1:-}" == "" ]] && {
    echo "Must specify MAJOR.MINOR.PATCH of python to fetch";
    exit 1;
}

fetch_py_tgz "${1}"
```

### Caveat: Extracting Python

This allowed projects to build their projects (with the help of some shared biuld scripts that would pick out the appropriate Python version among the numerous ones installed in the shared build image). However, once the Python applications were built in the build stage, and then copied over to the final output runner stage, the "clean" image of the runner wouldn't be able to fully install the Python app even though it's been built because there's no Python!

Re-building/installing Python on a per-project/service team basis wouldn't be good, because it loses the contract of each/all project leveraging the same set of versions, and defeats the purpose of the shared/vetted build image.

So, the solution was to extract the required Python version's bits from the build image; The best way I came up with that was like so:

```dockerfile
# ...
# Inside the final output/runner image stage in the multi-stage Dockerfile
# for the app

# Copy the Python bits from the build image:
COPY --from=org/common-build-image /usr/local/bin/python3.12* /usr/local/bin/
COPY --from=org/common-build-image /usr/local/lib/python3.12 /usr/local/lib/python3.12

# Establish as default Python:
RUN ln -s /usr/local/bin/python3.12 /usr/local/bin/python && \
    ln -s /usr/local/bin/python3.12 /usr/local/bin/python3 && \
    echo 'alias pip="python3.12 -m pip"' >> /etc/bash.bashrc && \
    echo 'alias pip3="python3.12 -m pip"' >> /etc/bash.bashrc

# COPY over built bits from the prior build stage
COPY --from=builder /usr/local/output.whl /usr/local/
RUN pip install -y /usr/local/output.whl && \
    rm /usr/local/output.whl
```

This works, doesn't particularly look nice, and requires each service team to know how/where to fetch the Python version from the shared build image, as well as re-implementing this bit of logic for every Python application they manage.

## docker buildx bake

We already leverage `docker buildx` for other features, and I recently stumbled across the `bake` feature set, which piqued my interests. I thought it'd be interesting to play around with what it would look like to build a set of dedicated "slim" Python Ubuntu images using this, so that down the road, service team's wouldn't need to to the [extracting Python hack bit](#caveat-extracting-python) for each of their apps. I realize I could just use `docker-compose` to get effectively the same thing, but since we don't otherwise use compose, I wanted to see what it would look like using only `buildx`.

Ultimately, I'd like to make it so that alongside the common build image, we _also_ output a set of N "slim" Python Ubuntu images, so that instead of inheriting from a stock Ubuntu image, and then doing the Python extraction, service teams could just `FROM <appropriate "slim" Python img>` as their end runner image.

### Approach

1. Define a top level bake HCL file that states the dependency linkage between the base/child images
1. Define one "base" build image (this should be effectively same as original base image from [the intial approach](#initial-approach) `Dockerfile`)
1. Define N additional "slim" Python Ubuntu based `Dockerfile`s
1. Define new build scripts that now how to use `docker buildx bake`
    * Build, publish, etc. accordingly

#### Step 1: HCL

We want to define that by default, every target (so base+all children) get built.

We also want to make it so that as part of the children's dockerfiles, we can leverage
the shared base image; this is made possible by the `context = { ... }` block, where
we are specifying that the `ubu-2404-plox-builder` image (which you'd use exactly the
same named in the `FROM ...` statement in that child's dockerfile), is dependent on the
builder target stage's output.

For now, we just build for `arm64` (but you could do multi-platform builds/publishing,
just extend them in the platforms array); Refer to
[the docker buildx bake docs](https://github.com/docker/buildx/blob/master/docs/reference/buildx_bake.md)
for a full reference on what is possible for the bake file.

Example of the defined HCL build file for the bake command is below:

`docker-python-bake.hcl`:

```hcl
group "default" {
    targets = ["builder", "python311", "python312", "python313"]
}

target "builder" {
    dockerfile = "Dockerfile.builder"
    tags = ["docker.io/codeplox-dev/ubu2404-python-base"]
    platforms = [
      #"linux/amd64",
      "linux/arm64",
    ]
}

target "python311" {
    dockerfile = "Dockerfile.python311"
    tags = ["docker.io/codeplox-dev/ubu2404-python-311"]
    platforms = [
      #"linux/amd64",
      "linux/arm64",
    ]
    contexts = {
        ubu2404-plox-builder = "target:builder"
    }
}

target "python312" {
    dockerfile = "Dockerfile.python312"
    tags = ["docker.io/codeplox-dev/ubu2404-python-312"]
    platforms = [
      #"linux/amd64",
      "linux/arm64",
    ]
    contexts = {
        ubu2404-plox-builder = "target:builder"
    }
}

target "python313" {
    dockerfile = "Dockerfile.python311"
    tags = ["docker.io/codeplox-dev/ubu2404-python-313"]
    platforms = [
      #"linux/amd64",
      "linux/arm64",
    ]
    contexts = {
        ubu2404-plox-builder = "target:builder"
    }
}
```

#### Step 2: base

The base image's Dockerfile looks identical to the one in the original approach. Fetching/altinstalling/configuring Python(s) works exactly the same, except now we store it in a `Dockerfile.builder`.


#### Step 3: children

The additional N `Dockerfile.python3XX` files looks identical to each other
(and also end up looking like what each project used to have to do individually
in their runner's stage), just with the only difference
being the version of the Python bits copied out; example, for Python3.11:

```dockerfile
ARG UBUNTU_VERS=ubuntu:noble-20241118.1

###############################################################################
# Python 311 output
###############################################################################
FROM ${UBUNTU_VERS}

SHELL ["/bin/bash", "-c", "-l"]
WORKDIR /root

COPY --from=ubu2404-plox-builder /usr/local/bin/python3.11* /usr/local/bin/
COPY --from=ubu2404-plox-builder /usr/local/lib/python3.11 /usr/local/lib/python3.11

RUN apt-get update && apt-get upgrade -yq
```

> (The `--from=ubu2204-plox-builder` image name comes from information we specified in the
HCL file in step 1)

#### Step 4: Make

The following will bake the `default` target, and load the resulting images into the
local machione's docker image registry:

```bash
docker buildx bake --load \
    -f docker-python-bake.hcl \
    --progress plain \
    --no-cache
```

If you wanted to push, you could use `--push` instead, just be sure that the output
in the HCL's `tags` section for each image is fully scoped to a proper registry and that
you've authed to those registry(s) accordingly.

Once published, end users could now just `FROM <image>` as their end-stage runner image
base, and not have to worry about copying over the appropriate bits from the base image
to have the correct Python setup for their application.

## Thoughts

Is this any better than just using the original single Dockerfile and just having to specify
`--targets` and invoking the `docker buildx build ...` command multiple times? I don't know. Personally,
I'm not sure I think so. Especially with the duplication of the child Dockerfile.python3xx's, it seems
like it'd just be cleaner to have everything be in the one single Dockerfile and just have the additional
image building/publication happen "under the covers" as part of addiitional `docker buildx` invocations for the
appropriate targets as part of the CI's build scripts.

Let me know what you think! Have you tried the `docker buildx bake` before?

## Code

Source code for these snippets/examples are uploaded here:

* [codeplox-dev/example-ubu-py-containers](https://github.com/codeplox-dev/example-ubu-py-containers)
