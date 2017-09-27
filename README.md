# AngelSword
AngelSword是由python3编写的简易的cms漏洞检测框架。旨在帮助有安全经验的安全工程师对已知的应用快速发现漏洞。



# 使用用法
python3 AngelSword.py -u http://www.example.com 对url执行所有poc检测(暴力)                            

python3 AngelSword.py -l 列出所有poc

python3 AngelSword.py -s live800  搜索出live800的相关poc

python3 AngelSword.py -r all -t http://www.example.com 利用-s搜索到的所有poc进行检测

python3 AngelSword.py -m live800_downlog_filedownload -t http://www.example.com 单一目标执行live800 download任意文件下载漏洞检测

python3 AngelSword.py -m live800_downlog_filedownload -f vuln.txt 对vuln.txt中的所有url执行live800 downlog任意文件下载漏洞检测

python3 AngelSword.py -m live800_downlog_filedownload -e 调用系统中的vim编辑poc文件

python3 AngelSword.py -v 显示静态统计

python3 AngelSword.py -c poc路径校验



# 平台
MAC Linux



# 需要用到的模块
bs4
json
redis
urllib
pexpect
termcolor
hashlib
telnetlib
pymysql
pymongo


# 说明
1.部分代码参考网上公开的脚本
2.本工具只限于进行漏洞验证，如若因此引起相关法律问题，概不负责。

# bugs
hanmengzi1993@gmail.com

