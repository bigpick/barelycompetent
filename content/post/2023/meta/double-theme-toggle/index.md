---
title: "Fixing incorrect theme preference when using cookies and media preference"
date: 2023-04-30T01:24:55-05:00
url: "/meta/fixing-automatic-theme-with-prefers"
Description: |
    Fixing an edge case where users have to double click theme toggle
    when leveraging the prefers-color-scheme media scheme.
type: posts
categories:
 - meta
---

## Background

Since I updated my blog to enable a dark and light mode (I'm sorry Zeno), I've
noticed that when I visit the site, it properly sets the theme based on my color
preference. However, if I toggle the theme using the new toggle switch, it
doesn't change it until I click it twice.

### Info

As part of supporting both a dark and light mode for my site, I use a toggle
that allows the user to switch on demand.

However, I also base the color scheme on their media preference, if any, via
`prefers-color-scheme`.

The snippet for the theme toggling and setting is so:

```js {linenos=true}
const theme = window.localStorage && window.localStorage.getItem("theme");
const themeToggle = document.querySelector(".theme-toggle");
const isDark = theme === "dark";
var metaThemeColor = document.querySelector("meta[name=theme-color]");

if (theme !== null) {
  document.body.classList.toggle("dark-theme", isDark);
  isDark
    ? metaThemeColor.setAttribute("content", "#252627")
    : metaThemeColor.setAttribute("content", "#fafafa");
}

themeToggle.addEventListener("click", () => {
  document.body.classList.toggle("dark-theme");
  window.localStorage &&
    window.localStorage.setItem(
      "theme",
      document.body.classList.contains("dark-theme") ? "dark" : "light"
    );
  document.body.classList.contains("dark-theme")
    ? metaThemeColor.setAttribute("content", "#252627")
    : metaThemeColor.setAttribute("content", "#fafafa");
});
```

So, clicking the toggle will set the `theme` cookie in the browser's local
storage, which works perfect.

However, the problem came when I enabled automatic setting of the theme, e.g:

```scss
blockquote {
  color: $drac-quote;
  @media (prefers-color-scheme: dark) {
    color: $drac-quote;
    border-left: 3px solid $cyan;
  }

  @media (prefers-color-scheme: light) {
    color: $code-dark-bg;
    border-left: 3px solid $code-dark-bg;
  }

  [data-theme=dark] & {
    color: $drac-quote;
    border-left: 3px solid $cyan;
  }

  [data-theme=light] & {
    color: $code-dark-bg;
    border-left: 3px solid $code-dark-bg;
  }
}
```

Now, elements on the site have values based on whether or not the site is using
dark or light mode, but _also_ based on user's OS preference. This works nicely
so that if a user visits the site with their preference as dark, they'll see a
dark site automatically, and likewise for light.

The problem arises looking at lines 6 and 7 in the snippet above - basically, no
matter what the user's media preference, the toggle will always default to dark
on first click.

This means that if a user with a preference for a dark site clicks the toggle,
it will set the themes state to dark. Then, a second click on the toggle will
properly set it to light.

### Fix

I needed to account for the fact that despite the theme toggle being unset, the
user might have a preference already - and should set the theme toggle opposite
of that if so:

```js
// Detect the color scheme the operating system prefers.
function detectOSColorTheme() {
  if (chosenThemeIsDark) {
    document.documentElement.setAttribute("data-theme", "dark");
  } else if (chosenThemeIsLight) {
    document.documentElement.setAttribute("data-theme", "light");
  } else if (window.matchMedia("(prefers-color-scheme: dark)").matches) {
    document.documentElement.setAttribute("data-theme", "dark");
    localStorage.setItem("theme", "dark");   // Added this
  } else {
    document.documentElement.setAttribute("data-theme", "light");
    localStorage.setItem("theme", "light");  // Added this
  }
}
```
