# SharpLogDump
获取本地或远程服务器的4624日志(C#学习写着玩项目)
## 简介
获取本地或远程服务器的4624日志，默认为-i 7天，查询默认用户为-f administrator，默认条数-c 4
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
![图片](./1.png)
![图片](./2.png)

## 免责声明
本工具仅面向**合法授权**的企业安全建设行为，如您需要测试本工具的可用性，请自行搭建靶机环境。

在使用本工具时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。**请勿对非授权目标进行扫描。**

如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，作者将不承担任何法律及连带责任。

在安装并使用本工具前，请您**务必审慎阅读、充分理解各条款内容**，限制、免责条款或者其他涉及您重大权益的条款可能会以加粗、加下划线等形式提示您重点注意。 除非您已充分阅读、完全理解并接受本协议所有条款，否则，请您不要安装并使用本工具。您的使用行为或者您以其他任何明示或者默示方式表示接受本协议的，即视为您已阅读并同意本协议的约束。
