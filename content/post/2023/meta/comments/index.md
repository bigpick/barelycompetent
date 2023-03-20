---
title: "Adding comments to this blog via Giscus"
date: 2023-03-20T01:24:55-05:00
url: "/meta/adding-giscus-comments"
Description: |
    Ever wanted to say hi after reading one of my posts? Think something
    I said was wrong, interesting, stupid, or otherwise worthy of
    commentary? Well, good news, now you can easily tell me! This blog
    now supports comments and reactions via Giscus.
type: posts
categories:
 - meta
---

## Background

A good blog should include a system for consumers to provide feedback
to the authors. Static site generators tend to not lend themselves
nicely towards such systems natively.

When I started this site, I knew at some point I would need to do some
work to get a comment system set up. After weighing the options, I
decided on [Giscus][]. There is a plethora of articles online discussing
the alternatives, weighing each of their pros and cons, so I won't
reiterate them here.

## Theme

One thing I hadn't seen much discussion on was the custom themeing of
Giscus once integrated with your site.

Gisucs official supports the idea of a "theme" (see [creating new themes][]).
However, I wasn't able to find many contributed themes. It would be nice
to have a repository of some of the more popular developer colorschemes
implemented for Giscus' CSS values (Gruxbox, Dracula, Nord, etc...).

I started implementing my own, but after a few minutes I decided it was
probably not worth having to create/maintain yet another pile of CSS
code to make my site look slightly better than it would by default.

Instead, I opted to stick with the default GitHub themes provided by
Giscus, since I already like those enough, and they're a reminder
of the system itself (Giscus leverages GitHub discussions for the tracking
and maintenance of the blog's "comments").

The issue I had was with dark vs light mode.

Light mode GitHub themed comments looked good with the light mode of
this site, likewise for dark GitHub and dark mode. However, they did
_not_ look good with the opposing themed values.


Fortunately, after a short bit of searching, I found [this discussion in Giscus][issue].
Particularly, [this comment][] was exactly what I was searching for.

With a little bit of tweaking, I took the code that was in that
comment, and modified it so that I could leverage it as part of a
Hugo shortcode, supplying values to the `giscusAttributes` variable
via `config.toml` values, like so:

```javascript
function getGiscusTheme() {
  const theme = localStorage.getItem("theme");
  const giscusTheme = theme === "dark" ? "dark" : "light";
  return giscusTheme;
}

function setGiscusTheme() {
  function sendMessage(message) {
    const iframe = document.querySelector('iframe.giscus-frame');
    if (!iframe) return;
    iframe.contentWindow.postMessage({ giscus: message }, 'https://giscus.app');
  }
  sendMessage({
    setConfig: {
      theme: getGiscusTheme(),
    },
  });
}

document.addEventListener('DOMContentLoaded', function () {
  const giscusAttributes = {
    "src": "https://giscus.app/client.js",
    "data-repo": "{{ .Site.Params.giscus.repo }}",
    "data-repo-id": "{{ .Site.Params.giscus.repoID }}",
    "data-category-id": "{{ .Site.Params.giscus.categoryID }}",
    "data-mapping": "{{ default "pathname" .Site.Params.giscus.mapping }}",
    "data-strict": "{{ default "1" .Site.Params.giscus.strict }}",
    "data-reactions-enabled": "{{ default "1" .Site.Params.giscus.reactionsEnabled }}",
    "data-emit-metadata": "{{ default "0" .Site.Params.giscus.emitMetadata }}",
    "data-input-position": "{{ default "top" .Site.Params.giscus.inputPosition }}",
    "data-theme": getGiscusTheme(),
    "data-lang": "{{ default "en" .Site.Params.giscus.lang }}",
    "data-loading": "{{ default "lazy" .Site.Params.giscus.loading }}",
    "crossorigin": "anonymous",
    "async": "",
  };

  // Dynamically create script tag
  const giscusScript = document.createElement("script");
  Object.entries(giscusAttributes).forEach(([key, value]) => giscusScript.setAttribute(key, value));
  document.body.appendChild(giscusScript);

  // Update giscus theme when theme switcher is clicked
  const toggle = document.querySelector('.theme-toggle');
  if (toggle) {
    toggle.addEventListener('click', setGiscusTheme);
  }
});
```

The above is stored in a file at `layouts/partials/js/giscus.js`. Since
it is a shortcode, I can set/grab values from my site's `config.toml`
file, like so:

```toml
# ...
  [params.giscus]
    repo = "bigpick/barelycompetent"
    repoID = "MDEwOlJlcG9zaXRvcnkzMzg5MDYyMDM="
    categoryID = "DIC_kwDOFDNMW84CSoj3"
    mapping = "pathname"
    strict = "1"
    reactionsEnabled = "1"
# ...
```

The shortcode which includes the above code is stored at
`layouts/partials/giscus.html`:

```mustache
{{- if isset .Site.Params "giscus" -}}
  {{- if and (isset .Site.Params.giscus "repo") (not (eq .Site.Params.giscus.repo "" )) (eq .Type "post")
(eq (.Params.disable_comments | default false) false) -}}
  <script>
    {{ partial "js/giscus.js" . | safeJS }}
  </script>
  {{- end -}}
{{- end -}}
```

... which is ultimately included into the pages' source code via a
custom `footer.html` layout.

Take a look, let me know what you think. Leave a comment or reaction!



[Giscus]: <https://giscus.app/>
[creating new themes]: <https://github.com/giscus/giscus/blob/main/CONTRIBUTING.md#creating-new-themes>
[issue]: <https://github.com/giscus/giscus/issues/336>
[this comment]: <https://github.com/giscus/giscus/issues/336#issuecomment-1214366281>
