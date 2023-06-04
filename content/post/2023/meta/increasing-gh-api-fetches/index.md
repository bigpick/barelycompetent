---
title: "Leveraging GitHub Personal Access Tokens to include public code in static site pages"
date: 2023-05-06T01:24:55-05:00
url: "/meta/including-public-code-via-github-api-in-pages"
Description: |
    How I fixed an issue with the GitHub API and hugo build process
    using fine grained personal access tokens.
type: posts
categories:
 - meta
tags:
 - hugo
---

## Background

As part of my site, I have a custom Hugo shortcode that enables me to include
code from any public GitHub repository via the API. This shortcode worked great
for me for a long time, but now that my site has grown and the number of pages
I'm including has gotten so large, I've begun being ratelimited by GitHub.

At the time that I added the custom shortcode, I was only fetching a handful of
pages. As such, I just took advantage of the fact that every repository was
public, and used the public GitHub API to fetch them.

However, I soon ran into an issue as I added more and more included pages:
GitHub rate limits public downloads:

- https://docs.github.com/en/rest/overview/resources-in-the-rest-api?apiVersion=2022-11-28#rate-limiting

### Solution

The solution was simple: simply don't use the unauthenticated API. The only
wrinkle to this was that I needed to modify the Hugo shortcode for the API
fetching to be able to securely leverage a PAT.

Originally, the bit that fetched the contents from the GitHub API looked like
so:

```liquid
{{ $dataJ := getJSON "https://api.github.com/repos/"  (.Get "repo")  "/contents/"  (.Get "file")  }}
```

To be able to bypass the rate limiting, I needed to pass the access token as
part of the query to the API.

To do so in Hugo, you can leverage the ability to
[Add HTTPS headers](https://gohugo.io/templates/data-templates/#add-http-headers)
when using the `getJSON` method:

```diff
-{{ $dataJ := getJSON "https://api.github.com/repos/"  (.Get "repo")  "/contents/"  (.Get "file")  }}
+{{ $tok := getenv "HUGO_GH_TOK" }}
+{{ $url := printf "https://api.github.com/repos/%s/contents%s" (.Get "repo") (.Get "file") }}
+{{ $headers := dict "Authorization" (printf "Bearer %s" $tok) }}
+{{ $dataJ := getJSON $url $headers }}
 {{ $con := base64Decode $dataJ.content }}
```

Now, I just need to setup `HUGO_GH_TOK` locally when building, and as a secure
envar in Netlify, and I have greatly increased rate limits to the API.

As a side bonus - now I can fetch private repos, too!
