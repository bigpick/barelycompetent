---
title: "Navigating enterprise productivity: Python code standards"
date: 2024-03-19T01:24:55-05:00
url: "/misc/career/productivity/enterprise_py_code_standards"
Description: |
    Effective collaboration on a project is a tricky thing to get right; Effective
    colloboration on an enterprise software project that often outlives the
    varying group of folks working on it is especially tricky. Here are some tips
    and tricks that we have adopted for Python development
    to make all our lives easier.
type: posts
sidebar_toc: true
categories:
 - misc
 - career
---

## Background

I have the awesome fortune to work on a team with a group of highly technically talented
developers. With such experienced developers often comes highly experienced (read: _opinionated_)
input.

Navigating a landscape where there is such high talent and opinions with a focus on
productivity and rapid development requires some level of compromise for all included
parties.

To alienate individuals as little as possible, a common, organization wide standard for
a given technology is established as part of its initial adoption. Once the standards
are put in place, whose formings are a collaborative process, it is expected that
all developers, regardless of seniority, experience, time withing the team/project, or
any other variable, adopt and leverage such practices from then on for that project
type without any argument.

By having an agreed upon hard standard, the chance for particular opinions causing
problems is given no room. In turn, once the standards have been worked out, the
potential for recurring tech debt and time waste on such areas are easily covered by
automation in a given individual's workflow.

## Python

This post specifically covers how we configure our Python projects, and their tooling's
configs, such that as an organization, we can leverage the above policy and gain the
benefit of a unified organization when it comes to development practices for this
specific area.

### pyproject.toml, a first pass

Initially, we used to track all of our tools (`black`, `ruff`, `mypy`, `pylint`, `pydocstyle`, etc.)
within each individual project's `pyproject.toml` file. These days, most tools support
such a concept, and we're already leveraging a `pyproject.toml` as part of our common
poetry based Python application layout, so extending the file to include our established
tooling standards was an easy choice.

For example, after a project's specific `pyproject.toml` content, across all projects,
we'd expect to have something like so in every repository:

```toml
[tool.pydocstyle]
[pydocstyle]
convention = "google"
match = '((?!_test).)*\.py'

[tool.black]
line-length = 100
include = '\.py$|.*scripts/python/.*$'
extend-exclude = '''
^/(
  (
      generated
    | .venv
    | .pipenv
    | thriftgen
    | .*\.pyi$
  )/
)
'''

[tool.pyright]
reportMissingImports = true
reportMissingTypeStubs = true
typeCheckingMode = "strict"
useLibraryCodeForTypes = true

[tool.mypy]
warn_return_any = true
warn_unused_configs = true
exclude = [
    'thriftgen*',
    'generated*',
    '.venv*',
    '.pipenv*',
]
ignore_missing_imports = false
disallow_untyped_calls = true
disallow_untyped_defs = true
disallow_incomplete_defs = true
check_untyped_defs = true
disallow_untyped_decorators = true
warn_no_return = true
warn_unreachable = true
strict = true
```

This block of config was _always_ expected to be the same across every individual
project.

However, after a few projects, the shortcomings of this approach quickly became known;
Having to effectively duplicate our common configuration across _N_ (and growing) projects
was not ideal at all. As new projects were onboarded, it required they properly copy
the right values; If standards were ever changed or new tools added, it required
updating all _N_ repositories at the same time to match the new requirements. Finally,
we had no way of being sure that the agreed upon standards were _actually_ the values
being used across all, or even a given single, repository without first looking at the
values themselves.

### Considering alternatives: the monolith

A quick Google search about `pyproject.toml` inheritance seems to suggest that leaving
a config out of a given project's `pyproject.toml` is fine _so long as_ you have a
`pyproject.toml` that is some number of directories above the applications folder, **upwards**
towards the git root of the repository.

The key part here being the **upwards** notion. A given tool can search from the applications
root up until the git root. This lends itself to naturally to a monolith based approach.
A single repository, which at the root has a `pyproject.toml` file that contains the above
block of common tool configs. Then, as subdirectories in that monolith repository,
a directory for each project's git repository.

While this solved our problem of having to duplicate our common config values, as well
as enforcing they are actually the ones being used for a given project, it introduced
a new design paradigm that we were trying to avoid for multiple reasons (that being
monolith based management). The reasons why our organization can't use a monolith based
layout is beyond the scope of this post, but in summary: building monoliths is a pain,
especially considering an existing CI/CD setup that assumes no such layout.

### Enter: organization wide common submodule

After some further consideration, we came across the final solution we use today; tracking
the _individual_ tool config files in a directory in our our org-wide submodule, and then
symlinking those config files to the root of project's given git repository.

The key was ditching the idea of using the `pyproject.toml` file, and instead, just
using each tool's individual config file. We already use an organization wide common
submodule across all our projects (whose details will maybe be in another post:) ), so
leveraging such a pattern just required splitting the once `pyproject.toml` contained
tool config subkeys to their respective files in the submodule and then a symlink
command.

That is, going from the `pyproject.toml` config above, we now have the following in our
submodule:

``` bash
ls our-org-wide-submodule/linters-formatters-confs/python
   mypy.ini
   pyrightconfig.json
   ruff.toml
   .pydocstyle.ini
```

And each file's contents are now just the same that were originally in the duplicated
`pyproject.toml` files:

```bash
cd our-org-wide-submodule/linters-formatters-confs/python
```

* `cat mypy.ini`: **n.b.:** This is slightly different than the `pyproject.toml` config.
  Unlike the others, the syntax for the `mypy` tool is somewhat different than the others
  (reference [mypy config](https://mypy.readthedocs.io/en/stable/config_file.html)).

    ```ini
    [mypy]
    exclude = (?x)(
        ^thriftgen.*
        | ^generated.*
        | ^\.venv.*
        | ^\/direnv.*
        | ^\.pipenv.*
        | ^test/.*
        | ^docs/.*
    )
    warn_no_return = true
    warn_unreachable = true
    ignore_missing_imports = false
    disallow_any_unimported = true
    disallow_untyped_calls = true
    no_implicit_optional = true
    show_error_codes = true
    strict = true
    ```

* `cat pyrightconfig.json`

    ```json
    {
        "reportMissingImports": true,
        "reportMissingTypeStubs": true,
        "typeCheckingMode": "strict",
        "useLibraryCodeForTypes": true
    }
    ```

* `cat ruff.toml`

    ```toml
    # Same as Black.
    line-length = 100
    indent-width = 4

    [lint]
    # Enable Pyflakes (`F`) and a subset of the pycodestyle (`E`)  codes by default.
    # Unlike Flake8, Ruff doesn't enable pycodestyle warnings (`W`) or
    # McCabe complexity (`C901`) by default
    select = ["D", "E", "F", "W", "I", "N", "UP", "ANN", "Q", "RUF"]

    ignore = [
      "ANN101", # Missing type annotation for {name} in method
      "ANN202", # Missing return type annotation for private function {name}
      "ANN204", # Missing return type annotation for special method
      "ANN206", # Missing return type annotation for classmethod {name}
      "ANN401", # Dynamically typed expressions (typing.Any) are disallowed in {name}
      "D105",   # Missing docstring in magic method
      "D412",   # No blank lines allowed between a section header and its content ("{name}")
      "RUF010",
      "UP006",
      "UP007"
    ]

    # Allow fix for all enabled rules (when `--fix`) is provided.
    fixable = ["ALL"]
    unfixable = []

    # Allow unused variables when underscore-prefixed.
    dummy-variable-rgx = "^(_+|(_+[a-zA-Z0-9_]*[a-zA-Z0-9]+?))$"

    [lint.per-file-ignores]
    "test/*" = ["D", "ANN"]

    [format]
    # Like Black, use double quotes for strings.
    quote-style = "double"

    # Like Black, indent with spaces, rather than tabs.
    indent-style = "space"

    # Like Black, respect magic trailing commas.
    skip-magic-trailing-comma = false

    # Like Black, automatically detect the appropriate line ending.
    line-ending = "auto"

    # Enable auto-formatting of code examples in docstrings. Markdown,
    # reStructuredText code/literal blocks and doctests are all supported.
    #
    # This is currently disabled by default, but it is planned for this
    # to be opt-out in the future.
    docstring-code-format = true

    # Set the line length limit used when formatting code snippets in
    # docstrings.
    #
    # This only has an effect when the `docstring-code-format` setting is
    # enabled.
    docstring-code-line-length = "dynamic"

    [lint.pydocstyle]
    convention = "google"
    ```

* `cat .pydocstyle.ini`

    ```ini
    [pydocstyle]
    convention = "google"
    match = '((?!_test).)*\.py'
    ```

To setup a new Python repository, all you have to do is ensure that the submodule is in
place, and then symlink the files:

```bash
ln -s our-org-wide-submodule/linters-formatters-confs/python/* . && \
  ln -s our-org-wide-submodule/linters-formatters-confs/python/.pydocstyle.ini .
```

Updates to the configuration files now automatically are picked up and enforced on
submodule update across any repository. Editors and IDEs all support reading the config
files from the root directory of the git repository, so we have automatic enforcement as
well; problem solved.

Oh, and we also switched from `black` to `ruff` - Which I'll surely explain in a later post,
too:)

## Final thoughts

Navigating exteremely talented technical developer's (usually) differing opinions is
a fine art. Working together to establish agreed upon standards, and coming up with a
sane way to ensure such practices are automatically tracked and enforced greatly helps
alleviate that strain. Try it out - after all, anytime not spent on arguing over linting/config
is time available for actual development (or, meetings, if you're unlucky...)
