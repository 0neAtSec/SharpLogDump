# SharpLogDump
获取本地或远程服务器的4624日志(C#学习写着玩项目)
## 简介
获取本地或远程服务器的4624日志，默认为-i 7天，查询用户为-f administrator
## 使用说明
```
SharpLogDump.exe -help

SharpLogDump.exe:
    Get the 4624 security logs of the local or remote server.
Usage:
    SharpLogDump.exe -help
    SharpLogDump.exe -i 10 -f zhangsan
    SharpLogDump.exe -h dc-ip -u administrator -p password -d domain -f zhangsan
    execute-assembly /path/to/SharpLogDump.exe
```
