# **DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded**

I honestly don’t understand why this works, but this is the payload to add in the search field

```
{{$on.constructor('alert(1)')()}}
```

It will not add the alert(1) to the rendered page so it is something on AngularJS directly.
