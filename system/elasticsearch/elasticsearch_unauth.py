#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: ElasticSearch未授权漏洞
referer: https://www.cnblogs.com/KevinGeorge/p/8038138.html
author: Lucifer
description: 该漏洞导致攻击者可以拥有Elasticsearch的所有权限。可以对数据进行任意操作。
'''
import sys
import warnings
import requests
import tempfile,sys
from elasticsearch import Elasticsearch
from termcolor import cprint
from urllib.parse import urlparse

sys.stderr=tempfile.TemporaryFile()

class elasticsearch_unauth_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        port = 9200
        if r"http" in self.url:
            #提取host
            host = urlparse(self.url)[1]
            try:
                port = int(host.split(':')[1])
            except:
                pass
            flag = host.find(":")
            if flag != -1:
                host = host[:flag]
        else:
            if self.url.find(":") >= 0:
                host = self.url.split(":")[0]
                port = int(self.url.split(":")[1])
            else:
                host = self.url

        try:
            es = Elasticsearch([host], port=port, timeout=6)
            if es.ping():
                cprint("[+]存在ElasticSearch未授权漏洞...(高危)\tpayload: "+host+":"+str(port), "red")
            else:
                cprint("[-]不存在elasticsearch_unauth漏洞", "white", "on_grey")

        except:
            cprint("[-] "+__file__+"====>可能不存在漏洞", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = elasticsearch_unauth_BaseVerify(sys.argv[1])
    testVuln.run()