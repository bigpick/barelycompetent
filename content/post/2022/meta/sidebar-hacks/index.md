---
title: "Why don't personal blog site themes ever include sidebars?"
date: 2022-11-21T01:24:55-05:00
url: "/meta/adding-fixed-sidebar-nav"
Description: |
  Every day I think more about how "developer documentation" sites are
  more suited for personal blogging than "blog" themes ever could be.
  For example, why don't any popular personal blog theme ever seem
  to come with a sidebar?
type: posts
categories:
 - meta
---

## Background

Take a look at a list of the most popular Hugo themes (by star count):

* [JamStack theme list][]
* [Fifty of 2022's most popular Hugo themes][]
* [100+ Best Hugo Themes (Hand-Picked For 2022)][]

What's one thing they almost all have in common? No per-page sidebar
navigation. This is something I've noticed since starting my journey of
personal blogging since ~2019: "personal blog" sites almost never
include some sort of in-page navigation.

I don't know _why_ blog site themes don't seem to include
in-page navigation via a sidebar-like object. If I had to guess, I'd
say blog theme authors seem to think that a single page doesn't
have that much content and wouldn't need intra-page navigation? Or
maybe sidebar-like navigation is "ugly" and would
break up the "clean" flow of a blog theme (which in my experience is
single container with a centered body div with large side padding, and not
much text other than the "main" article.)

Contrast the preceding to the general setup of "technical documentation"
type themes:

* [material mkdocs][]
* [Just The Docs][] (in issues currently)
* [Doks][]

Each theme comes with a per-page table of contents by default. If I
were to start a new blog from scratch (_for the third time_), I think
I would choose a technical documentation focused theme and customize
to me more "blog" like. This site is the opposite, however. It's a
blog focused theme that I've hacked to make more "technical" focused.

## Additions

I wanted to add a fixed sidebar nav element to this site. My requirements:

* It auto-populated based on headings contained on a page (I don't want
  to have to maintain a list manually)
* It tracked your current position in the page (via some sort of
  highlight/icon/w.e)
* It didn't overlap onto or mess with the ability to read a post's
  content.

### Inspiration

My attempt to hack a fixed sidebar into this side is based after the
work presented by Dakota Lee Martinez:

> [How to Add an Active Highlight to a Table of Contents In a Fixed Sidebar][]

I suggest reading their original post as they detail a bit of
information on the how and why of the approach that I don't plan
on reiterating here.

Aside from an _implementation_ approach, I was also inspired by the
likes of the previously mentioned mkdocs material sidebar tracker
as well.

### Outcome

If you viewed this site on a desktop, you might be thinking "but wait,
there _is_ a sidebar on this site?" My answer to that would be:

![well yes, but actually no meme](https://i.kym-cdn.com/entries/icons/original/000/028/596/dsmGaKWMeHXe9QuJtq_ys30PNfTGnMsRuHuo_MUzGCg.jpg)

The fixed sidebar that's now a part of this website was hacked in
using some effort that I'm sure would disgust any proper front end
developer. It's existence is very precarious, and only "works" properly
if viewed on a large viewport (screen).

If your device's screen is detected to be less than 1000 pixels
wide, then the nav content isn't rendered at all:

```scss
    // ...

    @media (max-width: 1000px) {
     display: none;
    }

    // ...
```

If you don't believe me, look at entirety of the horrid styling
file I managed to come up with:

* styling for the currently active header (not too bad):

    ```scss {linenos=true}
    .text-active {
      font-weight: bold;
      font-size: 1.1rem;
      @media (prefers-color-scheme: dark) {
        color: $purple;
      }

      @media (prefers-color-scheme: light) {
        color: $light-color-variant;
      }

      [data-theme=dark] & {
        color: $orange;
      }

      [data-theme=light] & {
        color: $light-color-variant;
      }
    }
    ```

* styling for the table of contents itself (_ick_):

    ```scss {linenos=true,linenostart=20}
    #toc {
        float: left;
        z-index: 20;
        width: 260px;
        padding-left: 10px;
        text-align: left;
        font-size: .9rem;
        display: flex;
        text-decoration: none !important;
        margin-left: 0px;

        ul {
          @media (max-width: 1100px) {
            float: none;
            width: 100px;
            margin-left: 5px;
          }
          margin-left: 15px;
          li {
            margin-left: 15px;
          }
          list-style-type: none;
          a {
            text-decoration: none !important;
          }
        }
    }

    #toc .tocLinks {
        position: fixed;
        width: 260px;
        list-style-type: none;
        font-size: 1rem;
        line-height: 1.2rem;
        //white-space: nowrap;
        white-space: wrap;
        overflow: auto;

        @media (max-width: 1400px) {
         float: none;
         width: 240px;
        }

        @media (max-width: 1300px) {
         float: none;
         width: 190px;
        }

        @media (max-width: 1200px) {
         float: none;
         width: 160px;
        }

        @media (max-width: 1100px) {
         float: none;
         width: 100px;
        }

        @media (max-width: 1000px) {
         display: none;
        }

        @media (prefers-color-scheme: dark) {
          scrollbar-color: $white $drac-black;
        }

        @media (prefers-color-scheme: light) {
          scrollbar-color: $drac-black $white;
        }

        [data-theme=dark] & {
          scrollbar-color: $white $drac-black;
        }

        [data-theme=light] & {
          scrollbar-color: $drac-black $white;
        }
    }
    ```

* styling for the "Table of Contents" title for the TOC:

    ```scss {linenos=true,linenostart=99}
    .tocLinks h5 {
        font-size: 1.3rem;
        margin-bottom: -10px;
        margin-top: 10px;
        @media (prefers-color-scheme: dark) {
          color: $white;
        }

        @media (prefers-color-scheme: light) {
          color: $light-color-variant;
        }

        [data-theme=dark] & {
          color: $orange;
        }

        [data-theme=light] & {
          color: $light-color-variant;
        }
    }
    ```

Lines 1-19 are responsible for coloring the currently active header
based on where the user has scrolled in the page, changing values based
on the current theme.

Lines 21-29 are what make the container for the TOC stick to the top
left hand side of the margin.

Lines 31-44 style the items in the table of contents itself, namely:
* disabling the underline text decoration for links
* setting the indentation width of sub-items

The nonsense that is lines 58-96 in the preceding snippets is my attempt
at getting the sidebar to be dynamically sized based on viewport, so as
to not overflow onto the main content.

I'm no front-end developer, but I'm fairly confident the preceding is _not how you're
supposed to do that_. The proper way to get this done would likely
require rewriting a fair amount of how this site's base theme is configured,
or switching to an entirely new theme altogether, where this layout is
included from the get-go. For now, this will have to do.

## Upcoming

As mentioned:

* consider researching means of re-writing current theme to include more
  proper in-page nav support
* consider switching to entirely new theme


[JamStack theme list]: <https://jamstackthemes.dev/theme/#ssg=hugo>
[Fifty of 2022's most popular Hugo themes]: <https://cloudcannon.com/blog/fifty-of-the-most-popular-hugo-themes/>
[100+ Best Hugo Themes (Hand-Picked For 2022)]: <https://themefisher.com/best-hugo-themes>
[Just The Docs]: <https://just-the-docs.github.io/just-the-docs/>
[material mkdocs]: <https://squidfunk.github.io/mkdocs-material/getting-started/>
[Doks]: <https://github.com/h-enk/doks>
[How to Add an Active Highlight to a Table of Contents In a Fixed Sidebar]: <https://dakotaleemartinez.com/tutorials/how-to-add-active-highlight-to-table-of-contents/>
