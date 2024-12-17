---
title: "Compare PEP440 versions"
date: 2024-12-13T00:00:00-00:01
url: "/one-offs/compare-pep440-versions"
Description: |
    Utility function for effectively comparing two PEP440 compliant version strings.
disable_comments: true
type: posts
sidebar_toc: false
categories:
 - one-offs
tags:
 - python
---


```python
>> from packaging.version import Version
>>
>> v1 = Version("1.2.3")
>> v2 = Version("1.2.3.post1")
>> v3 = Version("3.1.0.dev1")
>>
>> v1 < v2
True
>> v1 == v1
True
>> v3 > v2
True
```
