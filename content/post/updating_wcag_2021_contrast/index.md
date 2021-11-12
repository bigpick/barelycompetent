---
title: "Updates for better WCAG compliance: contrast"
date: 2021-11-11T09:24:55-05:00
categories:
 - Basics
---

### Web Content Accessibility Guidelines (WCAG)

> Web Content Accessibility Guidelines (WCAG) is developed through the W3C process in cooperation with individuals and organizations around the world, with a goal of providing a single shared standard for web content accessibility that meets the needs of individuals, organizations, and governments internationally.
>
> The WCAG documents explain how to make web content more accessible to people with disabilities. Web "content" generally refers to the information in a web page or web application...


Back when I created this site in early 2021, the driving inspiration for the theme was two fold:

1. (Mainly) The [dracula](https://github.com/dracula) theme.
2. My [initial pass at a Github pages hosted blog](https://bigpick.github.io/TodayILearned/).

If not obvious from the above, I **really** wanted the site to be dark themed; so much so that it was actually to a fault.

See, the state of the site ~10 months after its deployment has remained relatively unchanged in the theming/color department. Once I found a combination of colors that both sufficiently satisifed "dark mode", and paid homage to the [official Dracula palette](https://draculatheme.com/contribute), I stopped thinking about it. Why mess with the way the site looks after spending so much time fiddling with the sufficiently-dark-and-initially-pleasing-to-me colors?

Well, as it turns out, while my choices were dark, they were _too_ dark. Almost all text on my blog up to this point has been wildly failing important but often disregarded contrast tests.

### Contrast

As stated by Microsoft (in [documentation](https://docs.microsoft.com/en-us/microsoft-edge/devtools-guide-chromium/accessibility/accessibility-testing-in-devtools) for their devtools):

> **Contrast** defines whether an element can be understood by people with low vision.
> 
> * The [contrast ratio](https://www.w3.org/TR/WCAG21/#dfn-contrast-ratio) as defined by the [WCAG Guidelines](https://www.w3.org/TR/WCAG21/) indicates whether there is enough contrast between text and background colors. A green check mark icon indicates there's enough contrast, and an orange exclamation-point icon indicates there's not enough contrast.

#### Contrast Ratios

Contrast ratios can range from 1 to 21, commonly written 1:1 to 21:1. The first number representing the amount of contrast for the particular piece of content, higher meaning more contrast and being a better score.

According to WCAG, the **[minimum contrast](https://www.w3.org/TR/WCAG21/#contrast-minimum)** score in order to be a compliant piece of content:

> ... visual presentation of text and images of text has a contrast ratio of at least **`4.5:1`** ...

... while in order to meet the next level, or the **[enhanced contrast criterion](https://www.w3.org/TR/WCAG21/#contrast-enhanced)**:

> ... visual presentation of text and images of text has a contrast ratio of at least **`7:1`** ...

There's modifiers of these rules that slighlty change the required ratios depending on the size of the text, the location/usage of the text in a logo, and other factors that I've ommitted for the purposes of this post; We'll just consider the most basic requirement, which is regular sized font in mostly plain (body, etc) usage.


In order to actually calculate the contrast ratio, the formula is provided on the contrast ratio link from above:

> `(L1 + 0.05) / (L2 + 0.05)`
>
> where
>
> * `L1` is the [relative luminance](https://www.w3.org/TR/WCAG21/#dfn-relative-luminance) of the lighter of the colors, and
> * `L2` is the [relative luminance](https://www.w3.org/TR/WCAG21/#dfn-relative-luminance) of the darker of the colors.

and the values for L1 and L2 can be calculated using the formulas from the relative luminance link above:

> For the sRGB colorspace, the relative luminance of a color is defined as `L = 0.2126 * R + 0.7152 * G + 0.0722 * B` where **R**, **G** and **B** are defined as:
>
> * if RsRGB <= 0.03928 then R = RsRGB/12.92 else R = ((RsRGB+0.055)/1.055) ^ 2.4
> * if GsRGB <= 0.03928 then G = GsRGB/12.92 else G = ((GsRGB+0.055)/1.055) ^ 2.4
> * if BsRGB <= 0.03928 then B = BsRGB/12.92 else B = ((BsRGB+0.055)/1.055) ^ 2.4
>
> and RsRGB, GsRGB, and BsRGB are defined as:
>
> RsRGB = R8bit/255
> 
> GsRGB = G8bit/255
> 
> BsRGB = B8bit/255
>
> The "^" character is the exponentiation operator. (Formula taken from [[sRGB](https://www.w3.org/TR/WCAG21/#bib-sRGB)] and [[IEC-4WD](https://www.w3.org/TR/WCAG21/#bib-IEC-4WD)]).

Your browser's dev tools will do the above calculations for you, but for self-edification, let's try calculating it ourselves.

Consider the site's legacy header. It had background colored `#44475a` with foreground that was colored `#282a36`:

{{< image src="/img/wcag/original_site_header.png" alt="original_site_banner.png" position="center" style="border-radius: 8px;" >}}

The background color's calculations look like so:

```text
hex: #44475a
  R: 68 -> 68/255 -> RsRGB=0.266666666667 !<= 0.03928 -> R=((RsRGB+.055)/1.055) -> R=0.0578054301911
  G: 71 -> 71/255 -> GsRGB=0.278431372549 !<= 0.03928 -> G=((GsRGB+.055)/1.055) -> G=0.0630100176532
  B: 90 -> 90/255 -> BsRGB=0.352941176471 !<= 0.03928 -> B=((BsRGB+.055)/1.055) -> B=0.102241733088
```

And for the foreground (shortened):

```text
hex: #28236

R: 40 -> (((40/255)+.055)/1.055)^2.4 -> R=0.021219010376
G: 42 -> (((42/255)+.055)/1.055)^2.4 -> G=0.0231533661781
B: 54 -> (((54/255)+.055)/1.055)^2.4 -> B=0.0368894504011
```

Now to calculate the relative luminance, L:

```text
L = 0.2126 * R + 0.7152 * G + 0.0722 * B

L(back) = (0.2126*((((68/255)+.055)/1.055))^2.4)+(0.7152*((((71/255)+.055)/1.055)^2.4))+(0.0722*((((90/255)+.055)/1.055)^2.4)) = 0.0647360522131
L(fore) = (0.2126*((((40/255)+.055)/1.055))^2.4)+(0.7152*((((42/255)+.055)/1.055)^2.4))+(0.0722*((((54/255)+.055)/1.055)^2.4)) = 0.0237338674155
```

Now that we have L(fore) and L(back), we can calculate the contrast, using L(fore) as L(1) as it's the lighter color:

```text
(0.0647360522131 + .05) / (0.0237338674155 + .05)
```

Which gives us the final value, **`1.5560834693`**. If we check to see the value that we get from Chrome dev tools...

{{< image src="/img/wcag/original_site_header_contrast.png" alt="original_site_banner_contrast.png" position="center" style="border-radius: 8px;" >}}

It worked out! We calculated the same value that Chrome reads out. Manually calculating the contrast ratio of all your color combinations is not at all necesarry for reasons such as these (and other automated means of arriving to the same solution) but understanding _how_ that value is derived is now something you can brag about :)

So our calculated value of 1.55 matches the automatically detected value, but what does that tell us? Well, a score of 1.55 is well below the minimum contrast requirements of 4.5:1; this is indicated in the dev tools screenshot above by the little orange circled exclamation point.

So, the text in the header fails the lowest WCAG contrast compliance miserably, but what about the rest of the site?

* **Body text**:
  {{< image src="/img/wcag/original_site_body.png" alt="original_site_body.png" position="center" style="border-radius: 8px;" >}}

* **Splash/Home page**:
  {{< image src="/img/wcag/original_site_splash.png" alt="original_site_splash.png" position="center" style="border-radius: 8px;" >}}

* **List items**:
  {{< image src="/img/wcag/original_site_li.png" alt="original_site_li.png" position="center" style="border-radius: 8px;" >}}

* **Quotes**:
  {{< image src="/img/wcag/original_site_quote.png" alt="original_site_quote.png" position="center" style="border-radius: 8px;" >}}

* **Header (more)**:
  {{< image src="/img/wcag/original_site_logo.png" alt="original_site_logo.png" position="center" style="border-radius: 8px;" >}}

* **Menu pages**:
  {{< image src="/img/wcag/original_site_post_menu.png" alt="original_site_post_menu.png" position="center" style="border-radius: 8px;" >}}

Well, as you can see, it all fails. Basically, the only even-minimally compliant content was the large fonted section and page headers.

{{< image src="/img/wcag/original_site_page_header.png" alt="original_site_page_header.png" position="center" style="border-radius: 8px;" >}}

{{< image src="/img/wcag/original_site_page_subheader.png" alt="original_site_page_subheader.png" position="center" style="border-radius: 8px;" >}}


So I definitely could have done a better job at choosing colors. In trying to stick to the Dracula spec exactly, I ended up with carying combinations of text that just wasn't easy enough to read for most people.

The current appearance of the site is what I've settled on after taking a more accesibility-focused approach at color choices. I've tried to stick true to the Dracula color design, except this time, made sure to think of contrast from the start of the process.

I hope you enjoy the new look! (p.s. if you _do_, maybe you'll consider getting in on all things [Dracula UI](https://draculatheme.com/ui) 🧛 ?)

Happy hacking!


{{< gallery match="images/*" sortOrder="desc" rowHeight="150" margins="5" resizeOptions="600x600 q90 Lanczos" showExif=false previewType="blur" thumbnailHoverEffect="enlarge" embedPreview="true" loadJQuery="true">}}


