---
title: "Converting from Jekyll"
date: 2020-11-19T09:24:55-05:00
excerpt: "Some of my thoughts on transitioning from Jekyll to Hugo"
categories:
 - Basics
---

# Converting my old site

> Github Pages + Jekyll --> Netlify + Hugo + Google Domains

While there does exist [some tools for this kind of transition](https://gohugo.io/tools/migrations/), since I was entirely changing my theme and stack, I figured I'd suck up doing any changes manually, as I didn't want to have to add another variable into the mix.

All in-all, my _content_ didn't really require much modification. Some of the more major things I changed as part of the process were:

* Custom Domain Name(s)
* Netlify hosting (as opposed to Github Pages)
* (TODO) Redirect old .github.io links/references to my new custom domain's pages.
* Front Matters
* Code block syntax
* Image syntax

## Custom Domain Name
I bought a custom domain for the site through [Google Domains](https://domains.google.com/). Since it's a `.dev`, it requires an SSL certificate to run properly, but Netlify gives us that for free! Yay Let's Encrypt!!

> Netlify offers free HTTPS on all sites, including automatic certificate creation and renewal...

### Domains

* barelycompetent.dev
* abarelycompetent.dev

## Front Matter

Changes from general form of:

```yaml
---
author: george_pick
layout: post
title: "..."
excerpt: "pwnable.kr challenge: bof"
categories: [pwn practice]
---
```

to

```yaml
---
title: "..."
date: 2020-11-19T09:24:55-05:00
excerpt: "Some of my thoughts on transitioning from Jekyll to Hugo"
categories:
 - c1
 - c2
---
```

Noticeable changes are dropping the author and layout type from each page, and inserting a creation date entry.

## Images

On my Jekyll blog, I used to reference an image like:


```jekyll
![alt-text](/some/path/to/the/image)
```

Where I also combined some additional Jekyll Liquid templating features to append the site's base url to that path, like `{{ site.baseurl }}`.

For this Hugo theme, I am opting to use the supported Image [shortcode](https://gohugo.io/content-management/shortcodes/), which looks like [this](https://github.com/rhazdon/hugo-theme-hello-friend-ng#image).

Here's a dirty little bit I used to just replace every original Jekyll image tag in my old blog to my new site's theme's image shortcode:

(Note: I am only sharing for how I handled this process... I do not recommend copy+pasting this, as it is an ugly mess, and likely not what you need)


{{< code language="bash" title="Something something lazy..." expand="Show code" collapse="Hide code" isCollapsed="true" >}}
#!/usr/bin/env bash

# VERY specific use case
# Convert my old Jekyll syntax'ed images to Hugo compatible shortcodes
# Original format was something like:
#   ![]({{ site.baseurl }}/path/to/image
# New format shortcode is like:
#   {{</* image src="/path/to/image" alt="<text>" position="..." style="..." */>}}
# See: https://github.com/rhazdon/hugo-theme-hello-friend-ng#image

# Dirty, dirty handling, but w/e
OLDIFS=$IFS && IFS=$'\n'
matches=$(find . -type f -name '*.md' -exec grep -H '!\[\]({{ site.baseurl }}' {} \;)

for match in $matches; do
    #./<file>:![]({{ site.baseurl }}/.....
    to_replace="${match##*!}"
    to_replace="!$(echo $to_replace | sed 's/\[/\\\[/g' | sed 's/\]/\\\]/g')"
    echo $to_replace

    filename="${match/%:*/}"

    # Grab the image path
    path="/img$(echo "${match#*/img}" | cut -d')' -f1)"

    # Just use image name as alt text
    desc="${path##*/}"

    # Build shortcode
    shortcode='{{</* image src="'"${path}"'" alt="'"${desc}"'" position="center" style="border-radius: 8px;" */>}}'

    # Replace the original Jekyll image syntax with the shortcode:
    echo "sed -i 's|"${to_replace}"|"${shortcode}"|g'" ${filename} | bash
    sleep 0.5
done

IFS=$OLDIFS
{{< /code >}}

## Code block syntax

This theme uses [prism.js](https://prismjs.com/index.html) to highlight code blocks. My original site used [Rogue](https://kramdown.gettalong.org/syntax_highlighter/rouge.html)+[Pygments](https://pygments.org/) for Syntax highlighting, where you defined code blocks like so:

```jekyll
{% highlight <lang> %}
// code
{% endhighlight %}
```

Coming to this Hugo theme, which uses Prism, I can just define code like

``````
```lang
// code
```
``````

I ended up just achieving this by sed'ing out all the `{% highlight <lang> %}` with `` ```<lang>`` and `{% endhighlight %}` with `` ``` `` with Vim expressions.
