---
title: "Theme Markdown Basics"
date: 2020-11-18T09:24:55-05:00
url: "/theme-markdown-demo"
categories:
 - basics
tags:
 - markdown
---

# Markdown basics on this theme

Some example `code`:

```python
#!/usr/bin/env python3.8
from Crypto.PublicKey import RSA
from sympy.ntheory import factorint
# pip3.8 install factordb-pycli
from factordb.factordb import FactorDB

from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes

def check_factordb(N):
    factorized = FactorDB(N)
    factorized.connect()
    factor_list = factorized.get_factor_list()
    assert(len(factor_list) != 0 )
    return factor_list

def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
        gcd = b
    return gcd, x, y

def main():
    N = 580642391898843192929563856870897799650883152718761762932292482252152591279871421569162037190419036435041797739880389529593674485555792234900969402019055601781662044515999210032698275981631376651117318677368742867687180140048715627160641771118040372573575479330830092989800730105573700557717146251860588802509310534792310748898504394966263819959963273509119791037525504422606634640173277598774814099540555569257179715908642917355365791447508751401889724095964924513196281345665480688029639999472649549163147599540142367575413885729653166517595719991872223011969856259344396899748662101941230745601719730556631637
    e = 65537
    ct = 320721490534624434149993723527322977960556510750628354856260732098109692581338409999983376131354918370047625150454728718467998870322344980985635149656977787964380651868131740312053755501594999166365821315043312308622388016666802478485476059625888033017198083472976011719998333985531756978678758897472845358167730221506573817798467100023754709109274265835201757369829744113233607359526441007577850111228850004361838028842815813724076511058179239339760639518034583306154826603816927757236549096339501503316601078891287408682099750164720032975016814187899399273719181407940397071512493967454225665490162619270814464

    print("N: ", N)
    print("e: ", e)

    factors = check_factordb(N)
    if len(set(factors)) == 1 and len(factors) == 2:
        # p = q = sqrt(N)
        print(f"p = q = srqt(N) = {factors[0]}")
        phi = factors[0] * (factors[0] - 1)
    else:
        phi = 1
        for factor in factors:
            print(f"factor: {factor}")
            phi *= (factor-1)

    # Compute modular inverse of e
    gcd, d, b = egcd(e, phi)
    print("d:  " + str(d) );

    # Decrypt
    pt = pow(ct, d, N)
    print("Plaintext: ", pt)

if __name__=='__main__':
    main()
```

# Header 1
Bleep.

## Header 2
Bloop.

### Header 3
Blop.

#### Header 4
Blerg.

##### Header 5
Blong.

###### Header 6
Zomg.


Here is a line break:

---

Here's a nice quote:

> I don't care if it works on your machine! We are not shipping your machine!
> -- Vidiu Platon

To-do list:

1. Convince Senior devs to switch to using YAML.
2. ???
3. Profit.

And here are some of my favorite things:

* [LiveOverflow](https://liveoverflow.com/)'s awesome Youtube channel.
* Weekend [CTF](https://ctftime.org/user/75695)s
* Video Gaming

For those of you who like tables:

| Header 1 | Header 2 | Header 3 |
|----------|----------|----------|
| Entry 1  | Entry 2  | [Entry 3]()  |
| Entry 4  | Entry 5  | Entry 6  |

---

**Built in code shortcodes:**

Syntax is like so:

```hugo
{{</* code language="<lang>" title="..." expand="..." collapse="..." isCollapsed="..." */>}}
… code …
{{</* /code */>}}
```

Supported properties:

* `src` (required)
* `alt` (optional)
* `position` (optional, default: left, options: [left, center, right])
* `style`

Example, collapsed by default:

{{< code language="python" title="An example code shortcode" expand="Show code..." collapse="Hide" isCollapsed="true" >}}
def main():
  print("Hello, World!")

if __name__ == '__main__':
  main()
{{< /code >}}

… or not:

{{< code language="go" title="Some sample Go code via shortcode" expand="Give it to me" collapse="Go Away" isCollapsed="false" >}}
package main

import "fmt"

/*
  Once upon a time...
*/

type Vampire struct {
  Location   string
  BirthDate  int
  DeathDate  int
  Weaknesses []string
}

func (v *Vampire) Age() int {
  return v.calcAge()
}

func (v *Vampire) calcAge() int {
  return v.DeathDate - v.BirthDate
}

// ...there was a guy named Vlad

func main() {
  dracula := &Vampire{
    Location:   "Transylvania",
    BirthDate:  1428,
    DeathDate:  1476,
    Weaknesses: []string{"Sunlight", "Garlic"},
  }

  fmt.Println(dracula.Age())
}
{{< /code >}}
