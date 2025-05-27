---
title: "Aligning syntax highlighting to the site theme"
date: 2025-05-20T00:00:00-00:01
url: "/hugo-sntax-highlighting-to-match-dynamic-theme"
Description: |
    A fresh new take on code syntax highlighting to make
    browsing the site feel even more pleasing!
type: posts
sidebar_toc: false
categories:
 - meta
tags:
 - hugo
---

Historically, this site's syntax highlighting was _always_ Dracula.
Whether your device had a preferred dark/light media and/or whether
you toggled manually to either dark or light mode. I preferred having
a single source to manage, and preferred the code syntax to look the
same regardless.

Until now!

I realize that having lots of near-black blocks of code on an otherwise
very white page was perhaps jarring. In an effort to reduce such, I've
decided to enable separate syntax highlighting to align more with whether
the site is being rendered in dark or light mode.

## Originally

Originally, I had generated one file for the CSS variables for syntax
highlighting;

```bash
hugo gen chromastyles --style=dracula > assets/scss/dracula.scss
```

And then simply included them in the site's `custom.scss` like:

```scss
// ...
@import "./dracula.scss";

// ...
```

This worked, and applied syntax highlighting to blocks leveraging Chroma
well enough. The problem with this though, is that despite being able
to have a handle on whether the site is in dark mode or not (via `[data-theme="dark|light"]`
attribute selectors), there was no good way to toggle between this
file and another.

That is, you can't do something like

```scss
if [data-theme="dark"] then
    @import "./dracula.scss";
else
    @import "./light_syntax.scss";
fi
```

## Changes

After looking around for a while, I can across this set of resources:

* <https://bwiggs.com/posts/2021-08-03-hugo-syntax-highlight-dark-light/>
* <https://me.micahrl.com/blog/dark-mode/>

The first shows the following approach; inlining the style sheets directly
based on the media preference:

```html
<style type="text/css" media="screen">
  @media (prefers-color-scheme: dark) {
    {{ partial "css/syntax-dark.css" . | safeCSS }}
  }
  @media (prefers-color-scheme: light) {
    {{ partial "css/syntax-light.css" . | safeCSS }}
  }
</style>
```

Problem with this approach though is that we really want to be able to
base it off of the current `[data-theme="..."]` value that the theme
supports, and you can't easily include that directly inline.

That is where the second link comes in.

That page expands on the above by adding additional logic (particularly,
a `media` rule) and tying that rules value (either on, `all` or off,
`not all`) into the sites existing JS theme switcher.

So, the inline block looks like:

```html
    <style id="inlined-light-theme-styles" media="all and (prefers-color-scheme: light)">
      {{ partial "css/rose_pine_dawn_light.css" . | safeCSS }}
    </style>

    <style id="inlined-dark-theme-styles" media="all and (prefers-color-scheme: dark)">
      {{ partial "css/dracula_syntax.css" . | safeCSS }}
    </style>
```

Accordingly, in addition to setting the `data-theme` attribute in our theme toggler
JS, we also handle toggling the media rule:

```js
function detectOSColorTheme() {
  const darkThemeStyles = document.getElementById("inlined-dark-theme-styles");
  const lightThemeStyles = document.getElementById("inlined-light-theme-styles");

  if (chosenThemeIsDark) {
    document.documentElement.setAttribute("data-theme", "dark");
    darkThemeStyles.media = "all";
    lightThemeStyles.media = "not all";

  } else if (chosenThemeIsLight) {
    document.documentElement.setAttribute("data-theme", "light");
    darkThemeStyles.media = "not all";
    lightThemeStyles.media = "all";

  } else if (window.matchMedia("(prefers-color-scheme: dark)").matches) {
    document.documentElement.setAttribute("data-theme", "dark");
    localStorage.setItem("theme", "dark");
    darkThemeStyles.media = "all";
    lightThemeStyles.media = "not all";

  } else {
    document.documentElement.setAttribute("data-theme", "light");
    localStorage.setItem("theme", "light");
    darkThemeStyles.media = "not all";
    lightThemeStyles.media = "all";
  }
}
```

The result? The ability to toggle two entirely separate Hugo managed
syntax highlighting themes in-tandem with our site's theme!

Check out the new ligh mode syntax highlighting and let me know what
you think!
