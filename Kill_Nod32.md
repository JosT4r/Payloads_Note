# 一条命令干掉nod32
```
wmic product where name="ESET Security" call uninstall /nointeractive

PS: 管理员权限，可以卸载，但不建议这么做，动静太大，除非长期无人值守
```
