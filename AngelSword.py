#!/usr/bin/env python
# -*- coding: utf-8 -*-
#Author: Lucifer
#Prog: Main
#date: changeby 2017-8-21 
import os
import re
import io 
import sys
import time
import requests
import warnings
from termcolor import cprint
from urllib.parse import urlparse
from information.informationmain import *
from cms.cmsmain import *
from pocdb import pocdb_pocs
from industrial.industrialmain import *
from system.systemmain import *
from hardware.hardwaremain import *
from multiprocessing import Pool
from multiprocessing.dummy import Pool as ThreadPool
warnings.filterwarnings("ignore")
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
SEARCH_HISTORY = dict()

#版本号
VERSION = 'v2.0'

FLAGLET = '''
   / \   _ __   __ _  ___| / ___|_      _____  _ __ __| |
  / _ \ | '_ \ / _` |/ _ \ \___ \ \ /\ / / _ \| '__/ _` |
 / ___ \| | | | (_| |  __/ |___) \ V  V / (_) | | | (_| |
/_/   \_\_| |_|\__, |\___|_|____/ \_/\_/ \___/|_|  \__,_|
               |___/
                                        Code By Lucifer.
    '''

threads_num = 10
#并行任务池
cmspool = ThreadPool()
cmspool = ThreadPool(threads_num)
industrialpool = ThreadPool()
industrialpool = ThreadPool(threads_num)
systempool = ThreadPool()
systempool = ThreadPool(threads_num)
hardwarepool = ThreadPool()
hardwarepool = ThreadPool(threads_num)
informationpool = ThreadPool()
informationpool = ThreadPool(threads_num)

def informationprint(informationname):
    msg = ">>>Scanning information vulns.."
    sys.stdout.write(msg+informationname+" "*(len(msg)+10)+"\r")
    sys.stdout.flush()
    time.sleep(0.5)

def informationcheck(informationpoc):
    informationpoc.run()

def informationpoc_check(informationurl):
    poc_class = pocdb_pocs(informationurl)
    poc_dict = poc_class.informationpocdict
    cprint(">>>Information漏洞扫描URL: "+informationurl+"\t可用POC个数["+str(len(poc_dict))+"]", "magenta")
    informationpool.map(informationprint, poc_dict.keys())
    print("\r")
    results = informationpool.map(informationcheck, poc_dict.values())
    informationpool.close()
    informationpool.join()

def cmsprint(cmsname):
    msg = ">>>Scanning cms vulns.."
    sys.stdout.write(msg+cmsname+" "*(len(msg)+10)+"\r")
    sys.stdout.flush()
    time.sleep(0.5)

def cmscheck(cmspoc):
    cmspoc.run()

def cmspoc_check(cmsurl):
    poc_class = pocdb_pocs(cmsurl)
    poc_dict = poc_class.cmspocdict
    cprint(">>>CMS漏洞扫描URL: "+cmsurl+"\t可用POC个数["+str(len(poc_dict))+"]", "magenta")
    cmspool.map(cmsprint, poc_dict.keys())
    print("\r")
    results = cmspool.map(cmscheck, poc_dict.values())
    cmspool.close()
    cmspool.join()

def industrialprint(industrialname):
    msg = ">>>Scanning industrial vulns.."
    sys.stdout.write(msg+industrialname+" "*len(msg)+"\r")
    sys.stdout.flush()
    time.sleep(0.5)

def industrialcheck(industrialpoc):
    industrialpoc.run()

def industrial_check(industrialurl):
    poc_class = pocdb_pocs(industrialurl)
    poc_dict = poc_class.industrialpocdict
    cprint(">>>工控漏洞扫描URL: "+industrialurl+"\t可用POC个数["+str(len(poc_dict))+"]", "magenta")
    industrialpool.map(industrialprint, poc_dict.keys())
    print("\r")
    results = industrialpool.map(industrialcheck, poc_dict.values())
    industrialpool.close()
    industrialpool.join()

def systemprint(systemname):
    msg = ">>>Scanning system vulns.."
    sys.stdout.write(msg+systemname+" "*len(msg)+"\r")
    sys.stdout.flush()
    time.sleep(0.5)

def systemcheck(systempoc):
    systempoc.run()

def system_check(systemurl):
    poc_class = pocdb_pocs(systemurl)
    poc_dict = poc_class.systempocdict
    cprint(">>>System漏洞扫描URL: "+systemurl+"\t可用POC个数["+str(len(poc_dict))+"]", "magenta")
    systempool.map(systemprint, poc_dict.keys())
    print("\r")
    results = systempool.map(systemcheck, poc_dict.values())
    systempool.close()
    systempool.join()

def hardwareprint(hardwarename):
    msg = ">>>Scanning hardware vulns.."
    sys.stdout.write(msg+hardwarename+" "*len(msg)+"\r")
    sys.stdout.flush()
    time.sleep(0.5)

def hardwarecheck(hardwarepoc):
    hardwarepoc.run()

def hardware_check(hardwareurl):
    poc_class = pocdb_pocs(hardwareurl)
    poc_dict = poc_class.hardwarepocdict
    cprint(">>>Hardware漏洞扫描URL: "+hardwareurl+"\t可用POC个数["+str(len(poc_dict))+"]", "magenta")
    hardwarepool.map(hardwareprint, poc_dict.keys())
    print("\r")
    results = hardwarepool.map(hardwarecheck, poc_dict.values())
    hardwarepool.close()
    hardwarepool.join()


def AngelSwordMain(checkurl):
    try:
        reqt = requests.get(checkurl, timeout=10, verify=False)
        #执行information漏洞poc检查
        informationpoc_check(checkurl)
        #执行cms漏洞poc检查
        cmspoc_check(checkurl)
        #执行工控漏洞poc检查
        industrial_check(checkurl)
        #执行系统漏洞poc检查
        system_check(checkurl)
        #执行硬件漏洞poc检查
        hardware_check(checkurl)

    except Exception as e:
        print(e)
        cprint(">>>>>>>>>超时", "cyan")

if __name__ == '__main__':
    usage=FLAGLET+'''
                                                %s
            天使之剑，指哪打哪!
    opt:
    ---------------------------------------------------
    -h              Get help
    -t              Target
    -u              Url
    -l              List avalible pocs
    -s              Search poc key words
    -m              Use poc module
    -f              Load urls file
    -r              With range
    -e              Edit Poc file(if have parameter '-m')
    -v              List scanner verbose
    -c              Checksum and clear
    ---------------------------------------------------
Usage: python3 AngelSword.py -u http://www.example.com 对url执行所有poc检测(暴力)
    1.python3 AngelSword.py -l 列出所有poc
    2.python3 AngelSword.py -s live800  搜索出live800的相关poc
    3.python3 AngelSword.py -m live800_downlog_filedownload -t http://www.example.com 单一目标执行live800 download任意文件下载漏洞检测
    4.python3 AngelSword.py -m live800_downlog_filedownload -f vuln.txt 对vuln.txt中的所有url执行live800 downlog任意文件下载漏洞检测
    6.python3 AngelSword.py -r all -t http://www.example.com 对搜索出来的poc进行指定范围批量测试。 使用前需要利用-s搜索。
    7.python3 AngelSword.py -m live800_downlog_filedownload -e 调用系统中的vim编辑poc文件
    8.python3 AngelSword.py -v 显示静态统计
    9.python3 AngelSword.py -c poc路径校验
        '''%VERSION
    if len(sys.argv) < 2 or sys.argv[1]=="-h":
        cprint(usage, "cyan")
    elif sys.argv[1] == "-l":
        #列出CMS POC名称
        pocclass = pocdb_pocs('')
        cmsclass = pocclass.cmspocdict
        print("\t\t\tCMS POC")
        for cms in cmsclass:
            print("|"+cms+"")
            print("|---------------------------------------------------------------------|")
        print("\r")

        #列出industrial POC名称
        pocclass = pocdb_pocs('')
        industrialclass = pocclass.industrialpocdict
        print("\t\t\tIndustrial POC")
        for industrial in industrialclass:
            print("|"+industrial+"")
            print("|---------------------------------------------------------------------|")
        print("\r")

        #列出SYSTEM POC名称
        pocclass = pocdb_pocs('')
        systemclass = pocclass.systempocdict
        print("\t\t\tSYSTEM POC")
        for system in systemclass:
            print("|"+system+"")
            print("|---------------------------------------------------------------------|")
        print("\r")

        #列出HARDWARE POC名称
        pocclass = pocdb_pocs('')
        hardwareclass = pocclass.hardwarepocdict
        print("\t\t\tHARDWARE POC")
        for hardware in hardwareclass:
            print("|"+hardware+"")
            print("|---------------------------------------------------------------------|")
        print("\r")
    elif sys.argv[1] == "-s" and sys.argv[2]:
        keywords = sys.argv[2].strip()
        count = 0
        cprint("搜索结果: ", "green")
        with open("pocdb.py", "r", encoding='utf-8') as f:
            for line in f.readlines():
                line = line.strip()
                if line.find(keywords) is not -1:
                    count += 1
                    line = line.split(":")
                    linename = line[0].rstrip('"').lstrip('"')
                    linepoc = line[1].replace("_BaseVerify(url),", "")
                    cprint("["+str(count)+"]漏洞名: "+linename+"=======>"+linepoc, "yellow")
                    SEARCH_HISTORY[str(count)] = linepoc
        if os.path.exists(".history") is True:
            os.remove(".history")
        f = open(".history", "a")
        for key, value in SEARCH_HISTORY.items():
            stringLine = key + "|" + value + "\r\n"
            f.write(stringLine)
    elif sys.argv[1] == "-m" and sys.argv[3] == "-f":
        #合并漏洞字典
        poc_class = pocdb_pocs("")
        alldict = dict()
        tmpdict = poc_class.informationpocdict.copy()
        alldict.update(tmpdict)
        tmpdict = poc_class.cmspocdict.copy()
        alldict.update(tmpdict)
        tmpdict = poc_class.systempocdict.copy()
        alldict.update(tmpdict)
        tmpdict = poc_class.industrialpocdict.copy()
        alldict.update(tmpdict)
        tmpdict = poc_class.hardwarepocdict.copy()
        alldict.update(tmpdict)
        for keyword in alldict.values():
            if keyword.__str__().find(sys.argv[2].strip()) is not -1:
                break
        cprint(FLAGLET, "cyan")
        sys.stdout.write("\033[1;35m[+] 加载poc: ["+keyword.__module__+"]\033[0m\n")
        statistic_count = 0
        filepath = sys.argv[4].strip()
        allcount = len(open(filepath,'rU').readlines())
        with open(filepath) as f:
            for line in f.readlines():
                statistic_count += 1
                line = line.strip()
                sys.stdout.write("\033[1;35m[+] 发送payload..\033[0m\n")
                sys.stdout.write("\033[1;35m[+] 正在攻击.."+line+"\033[0m\n")
                keyword.url = line
                keyword.run()
                print("[*] 攻击进度: [", end="")
                sys.stdout.write(str(statistic_count))
                cprint("/"+str(allcount)+"]"+"\r")
                sys.stdout.flush()

    elif sys.argv[1] == "-u" and sys.argv[2]:
        AngelSwordMain(sys.argv[2])
    elif sys.argv[1] == "-m" and sys.argv[3] == "-t":
        target = sys.argv[4].strip()
        poc_class = pocdb_pocs(target)
        alldict = dict()
        tmpdict = poc_class.informationpocdict.copy()
        alldict.update(tmpdict)
        tmpdict = poc_class.cmspocdict.copy()
        alldict.update(tmpdict)
        tmpdict = poc_class.systempocdict.copy()
        alldict.update(tmpdict)
        tmpdict = poc_class.industrialpocdict.copy()
        alldict.update(tmpdict)
        tmpdict = poc_class.hardwarepocdict.copy()
        alldict.update(tmpdict)
        for keyword in alldict.values():
            if keyword.__str__().find(sys.argv[2].strip()) is not -1:
                break
        cprint(FLAGLET, "cyan")
        cprint("[+] 加载poc: ["+keyword.__module__+"]", "cyan")
        cprint("[+] 发送payload...", "cyan")
        cprint("[+] 正在攻击.."+target, "cyan")
        keyword.run()
    elif sys.argv[1] == "-r" and sys.argv[3] == "-t":
        rangedict = dict()
        with open (".history") as f:
            for line in f.readlines():
                line = line.strip()
                rangedict[line.split("|")[0]] =  line.split("|")[1]
        if sys.argv[2] == "all":
            poclist = list()
            target = sys.argv[4].strip()
            poc_class = pocdb_pocs(target)
            alldict = dict()
            tmpdict = poc_class.informationpocdict.copy()
            alldict.update(tmpdict)
            tmpdict = poc_class.cmspocdict.copy()
            alldict.update(tmpdict)
            tmpdict = poc_class.systempocdict.copy()
            alldict.update(tmpdict)
            tmpdict = poc_class.industrialpocdict.copy()
            alldict.update(tmpdict)
            tmpdict = poc_class.hardwarepocdict.copy()
            alldict.update(tmpdict)
            cprint(FLAGLET, "cyan")
            for key, value in rangedict.items():
                poclist.append(value)
            for pocfuck in poclist:
                for keyword in alldict.values():
                    if keyword.__str__().find(pocfuck) is not -1:
                        break
                sys.stdout.write("\033[1;35m[+] 加载poc: ["+keyword.__module__+"]\033[0m\n")
                sys.stdout.write("\033[1;35m[+] 发送payload..\033[0m\n")
                sys.stdout.write("\033[1;35m[+] 正在攻击.."+target+"\033[0m\n")
                sys.stdout.flush()
                keyword.run()
        else:
            pass
    elif sys.argv[1] == "-m" and sys.argv[3] == "-e":
        targetfile = sys.argv[2].strip()
        targetfile = targetfile.replace("_BaseVerify","")
        #收集扫描文件路径
        tmppath = list()
        fullpath = list()
        curpath = os.getcwd()
        for dirpath, dirnames, filenames in os.walk(curpath):
            for file in filenames:
                if "__pycache__" not in dirpath and "__init__" not in file and ".pyc" not in file:
                    tmppath = os.path.join(dirpath, file)
                    if tmppath.strip() not in fullpath:
                        fullpath.append(tmppath)
        for selectpath in fullpath:
            if targetfile in selectpath:
                break
        ret = os.system("vim "+selectpath)
        if ret == 0:
            cprint("文件:"+targetfile+"======>编辑成功!", "green")
        else:
            cprint("文件:"+targetfile+"======>编辑失败!", "red")

    elif sys.argv[1] == "-v":
        poc_class = pocdb_pocs("")
        informationpocs = len(poc_class.informationpocdict)
        cmspocs = len(poc_class.cmspocdict)
        systempocs = len(poc_class.systempocdict)
        industrialpocs = len(poc_class.industrialpocdict)
        hardwarepocs = len(poc_class.hardwarepocdict)
        total = cmspocs + systempocs + industrialpocs + hardwarepocs + informationpocs
        flag = FLAGLET+'''
                                                %s
            漏洞poc统计
        '''%VERSION
        cprint(flag, "green")
        cprint("|-------------------------------------|","green")
        cprint("| Information漏洞POC个数:          "+str(informationpocs), "green")
        cprint("| CMS漏洞POC个数:                  "+str(cmspocs), "green")
        cprint("| SYSTEM漏洞POC个数:               "+str(systempocs), "green")
        cprint("| Industrial漏洞POC个数:           "+str(industrialpocs), "green")
        cprint("| HardWare漏洞POC个数:             "+str(hardwarepocs), "green")
        cprint("| 总漏洞POC个数:                   "+str(total), "green")
        cprint("| 扫描器线程个数:                  "+str(threads_num), "green")
        cprint("|-------------------------------------|","green")

    elif sys.argv[1] == "-c":
        fullpoc = list()
        tmppath = list()
        fullpath = list()
        curpath = os.getcwd()
        for dirpath, dirnames, filenames in os.walk(curpath):
            for file in filenames:
                if "__pycache__" not in dirpath and "__init__" not in file and ".pyc" not in file and "DS_Store" not in file and ".txt" not in file and ".xml" not in file and "AngelSword.py" not in file and "pocdb.py" not in file and "main.py" not in file:
                    tmppath = os.path.join(dirpath, file)
                    if tmppath.strip() not in fullpath:
                        fullpath.append(tmppath)

        with open("pocdb.py") as f:
            for line in f.readlines():
                line = line.strip()
                if line.find("BaseVerify") is not -1:
                    line = line.split(":")
                    linepoc = line[1].replace("_BaseVerify(url),", "")
                    fullpoc.append(linepoc)
        cprint(">>>执行poc路径校验判断...", "cyan")
        for singlepoc in fullpoc:
            for singlepath in fullpath:
                if singlepoc in singlepath:
                    fullpath.remove(singlepath)
        for tmppath in fullpath:
            if ".git" not in tmppath:
                cprint("[-]"+tmppath, "red")

    else:
        AngelSwordMain(sys.argv[1])
