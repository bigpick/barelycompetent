---
title: "Dracula enters the light?"
date: 2022-11-13T01:24:55-05:00
url: "/meta/adding-light-mode"
categories:
 - meta
---

## Previous state

Earlier this year I took a pass at updating this site for improved
accessibility; That post lives [here][].

At the end of that process, I shared [the new look of the site's sole
theme][]. Despite my love for dark themes, I realized that if I wanted
to use this site as valid means of blogging, I need to accommodate
people who don't share my same point of view on themes.


## New state

> Jump down to the [gallery displaying the latest version of the site][2]
> for an "after after" comparison.

When I made this site, I patched out the native dark/light mode support
this site's theme ([hello-friend-ng][]) natively supported. To get it
back, I reverted my clobbering of the toggle capabilities, and extended
the light values to match the "Dracula" scheme of this site.

Now this site offers a dark _and_ light mode, selectable via a toggle.
In fact, your preferred mode should've activated automatically
when you first visited thanks to `@media (prefers-color-scheme)`. Click
the little sun toggle in the menu bar to change the site appearance
manually.

### Accessibility

You should notice that the light mode is less colorful than the dark
variant. I had to change a bit of the more colorful options to use the
various darker shades of this theme to better meet Web Content
Accessibility Guidelines compliance requirements. This theme's neon
pink/cyan/green/etc. doesn't bode well when used against a light
(`#f8f8f2`) background, which makes sense given that the Dracula theme
[was not designed to ever be used as a light theme][1].

Despite this fact, I wanted to try to still keep the "vibe" as much as
possible. As such, the light mode leverages the dark components of the
spec -- background, current line, comment, or shades and variations of
them.

#### Links

Common conventions dictate that hyperlinks should generally consist of
some shade of blue. The [Dracula spec][] has just one option that is
close to blue, cyan. However, this color (`#8be9fd`) has poor
readability when used against a light background:

{{< image src="/img/2022/meta/light-mode/cyan_fg_fail.png" alt="cyan_fg_fail.png" position="center" style="border-radius: 8px;" >}}

Since the link color is going to be used sparsely, I was fine with using
a "non-Dracula" shade of blue (`#0F62FE`), which fairs much better (it
still fails level AAA).

### URL and Search Engine Optimizations (SEO) optimizations

I try to keep my local files organized by date, and sub-categorized by
category, so when I saw that this site supported automatically stubbing
the articles' dates in to their permalink locations, I got excited.

To do so, the following block must exist in your site's `config.toml`:

```yaml
[permalinks]
  posts = "/posts/:year/:month/:title/"
```

With the preceding in place, a page at a local path of
`/content/post/foo/bar/baz.md` with front matter of:

```yaml
---
title: "foo bar baz"
date: 2022-11-13
---
```

Would get rendered to `https://<your_site>/posts/2022/11/foo-bar-baz/`.

As I read more about ideal URL values for SEO performance, I realized
including dates in a page's URL hurts more than it helps (especially
since [Google considers your URLs as part of your ranking][]:

> 52. URL Path

> 55. Keyword in URL

> 56. URL String

In general, guidance seems to agree that:

* short is better than long
  * include as much key information in as little words as possible
* don't use dates (people aren't interested, and it dates your site)
* use hyphens
* be consistent
* less nesting the better

While the SEO optimzations, however little they may be, are nice, I
wanted a way to have more control and consistency over my URLs in
general. Originally, all posts on this site ended up looking like:

```
/posts/<title-of-post/
```

I wanted a way to include at least a category, and wanted to ideally
have it leverage existing Hugo capabilities. The existing Hugo
[permalink configuration values][] has a `:section` or `:sections` option,
but this blog's structure prevents using "proper" sections because
the pages fail to get listed on the list endpoints (example
[/post/](/post/)).

Maybe `:slug` could be used as a fake "category" field? Using:

```toml
[permalinks]
  posts = "/:slug/:title"
```

and

```yaml
title: "How to run docker in docker"
slug:  "containers"
date: 2022-11-13
```

Would result in a URL like `/containers/how-to-run-docker-in-docker`.

Slug's intended usage is an alternative to the page's title, meant to
replace the value at the _end_ of the URL; using it as a fake category
(near the front of the URL) seems cheesy.

I came to the conclusion to just specify the `url:` value in each
page's front matter. This approach is explicit, and I can control
where a page gets rendered, regardless of the local structure:

```yaml
---
title: "Some really long title about upgrading to Python 3.11
date: 2022-11-13
url: "/tutorials/upgrading-to-python-311"
---
```

Will always get rendered to `https://<site>/tutorials/upgrading-to-python-311`,
even if I move or reorganize my local file structure.

Making the switch over to this explicit URL approach means any existing
links for my site will be broken, but that's fine since I've not
widely publicized it before.


## Actual new site design with light mode gallery

{{< gallery match="actual_new_images/*" sortOrder="asc" rowHeight="150" margins="5" resizeOptions="600x600 q90 Lanczos" showExif=false previewType="blur" thumbnailHoverEffect="enlarge" embedPreview="true" loadJQuery="true">}}


[here]: </meta/dark-mode-accesibility-updates/>
[the new look of the site's sole theme]: </meta/dark-mode-accesibility-updates/#new-site-design-gallery>
[hello-friend-ng]: <https://github.com/rhazdon/hugo-theme-hello-friend-ng>
[1]: <https://github.com/dracula/dracula-theme#faq>
[Dracula spec]: <https://draculatheme.com/contribute#color-palette>
[Google considers your URLs as part of your ranking]: <https://backlinko.com/google-ranking-factors>
[permalink configuration values]: <https://gohugo.io/content-management/urls/#permalink-configuration-values>
[2]: <#actual-new-site-design-with-light-mode-gallery>

