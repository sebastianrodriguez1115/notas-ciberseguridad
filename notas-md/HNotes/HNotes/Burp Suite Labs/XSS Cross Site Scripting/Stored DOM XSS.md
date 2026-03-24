# **Stored DOM XSS**

I saved a payload from PayloadAllTheThings in the comment field on a post:

```
<><img src=1 onerror=alert(1)>
```

That payload was chosen because the system was trying to escape \<\> but was doing just the first occurrence.
