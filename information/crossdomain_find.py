#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: crossdomain.xml文件发现
referer: unknown
author: Lucifer
description: crossdomain错误配置可导致。
'''
import sys
import requests
import warnings
from termcolor import cprint

class crossdomain_find_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/crossdomain.xml"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"<cross-domain-policy>" in req.text and r"allow-access-from" in req.text:
                cprint("[+]存在crossdomain.xml文件发现漏洞...(信息)\tpayload: "+vulnurl, "green")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = crossdomain_find_BaseVerify(sys.argv[1])
    testVuln.run()
