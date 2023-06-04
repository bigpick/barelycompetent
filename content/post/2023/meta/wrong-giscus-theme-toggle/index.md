---
title: "Fixing incorrect giscus theme when using 'prefers' media scheme"
date: 2023-04-22T01:24:55-05:00
url: "/meta/fixing-automatic-giscus-theme-with-prefers"
Description: |
    Fixing an edge case where users have to double click theme toggle
    when leveraging the prefers-color-scheme media scheme in order for
    Giscus to have the appropriate color.
type: posts
categories:
 - meta
---

## Background

Since I updated my blog to enable a dark and light mode (I'm sorry Zeno) and a
custom Gisucs theme to match, I've noticed that the Giscus theme doesn't match
the theme of the website until I've toggled it back and forth twice.

### Info

Originally, I was using the following to get what value the Giscus comments
styling should be:

```js
function getGiscusTheme() {
  const theme = localStorage.getItem("theme");
  const giscusTheme = theme === "dark" ? "dark" : "light";
  return giscusTheme;
}
```

The problem with this though was that I also rely on setting the website's theme
based on users OS preference, if set.

This is done via the `prefers-color-scheme` value.

The problem then was that if a user visits the site with a preferred color
scheme, the theme of the blog gets set to that, but the local storage cookie for
the theme wasn't being set because the value for the theme was coming from their
preference, not the theme toggler.

### Fix

The fix was easy once I realized my mistake: I just needed to add a check to the
JS that sets the Giscus theme to also include the users preference, in the case
that the theme toggle based cookie hasn't been set yet:

```js
function getGiscusTheme() {
  let theme;

  if (window.matchMedia && (localStorage.getItem("theme") === null)) {
    // Check if the dark-mode Media-Query matches
    console.log("inside 1");
    if (window.matchMedia("(prefers-color-scheme: dark)").matches) {
      theme = "dark";
    } else {
      theme = "light";
    }
  } else {
    theme = localStorage.getItem("theme");
  }
  return theme === "dark" ? "dark" : "light";
}
```
