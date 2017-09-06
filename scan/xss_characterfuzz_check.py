#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: xss特殊字符/函数/标签 FUZZ检测
referer: unknown
author: Lucifer
description: FUZZ反射型跨站所需要的负载有无过滤情况。
'''
import re
import sys
import requests
import warnings
from termcolor import cprint

class xss_characterfuzz_check_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        key = "FUZZING"
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        start_md5 = "c28c0db26d39331a"
        end_md5 = "15b86f2d013b2618"
        character = [",", ".", "?", "<", ">", "/", ";", ":", "'", '"', "|", "\\", "[", "]", "{", "}", "=", "!", "@", "$", "%", "(", ")"
        ]
        drive_func = ['onabort ', 'onactivate ', 'onafterprint ', 'onafterupdate ', 'onbeforeactivate ', 
            'onbeforecopy ', 'onbeforecut ', 'onbeforedeactivate ', 'onbeforeeditfocus ', 'onbeforepaste ', 
            'onbeforeprint ', 'onbeforeunload ', 'onbeforeupdate ', 'onblur ', 'onbounce ', 'oncellchange ', 
            'onchange ', 'onclick ', 'oncontextmenu ', 'oncontrolselect ', 'oncopy ', 'oncut ', 'ondataavailable ', 
            'ondatasetchanged ', 'ondatasetcomplete ', 'ondblclick ', 'ondeactivate ', 'ondrag ', 'ondragend ', 
            'ondragenter ', 'ondragleave ', 'ondragover ', 'ondragstart ', 'ondrop ', 'onerror ', 'onerrorupdate ', 
            'onfilterchange ', 'onfinish ', 'onfocus ', 'onfocusin ', 'onfocusout ', 'onhelp ', 'onkeydown ', 'onkeypress ', 
            'onkeyup ', 'onlayoutcomplete ', 'onload ', 'onlosecapture ', 'onmousedown ', 'onmouseenter ', 'onmouseleave ', 
            'onmousemove ', 'onmouseout ', 'onmouseover ', 'onmouseup ', 'onmousewheel ', 'onmove ', 'onmoveend ', 
            'onmovestart ', 'onpaste ', 'onpropertychange ', 'onreadystatechange ', 'onreset ', 'onresize ', 
            'onresizeend ', 'onresizestart ', 'onrowenter ', 'onrowexit ', 'onrowsdelete ', 'onrowsinserted ', 'onscroll ', 
            'onselect ', 'onselectionchange ', 'onselectstart ', 'onstart ', 'onstop ', 'onsubmit ', 'onunload '            
        ]
        label_func = ['javascript ', 'vbscript ', 'expression ', 'applet ', 'meta ', 'xml ', 'blink ', 'link ', 
            'style ', 'script ', 'embed ', 'object ', 'iframe ', 'frame ', 'frameset ', 'ilayer ', 'layer ', 
            'bgsound ', 'title ', 'base ', 'img ', 'video '
        ]
        window_func = ['alert ', 'confirm ', 'prompt']
        rawurl = self.url.replace("FUZZING", start_md5)
        cprint(">>执行xss测试..", "cyan")
        req = requests.get(rawurl, headers=headers, timeout=6, verify=False)
        if start_md5 in req.text:
            cprint("[+]输入参数带入回显,可能存在XSS漏洞..", "red")

            #执行character 过滤FUZZ
            cprint(">>执行特殊字符FUZZ判断..", "cyan")
            characterlist = list()
            characterlist2 = list()
            for char in character:
                char = char.strip()
                rawurl = self.url.replace("FUZZING", start_md5 + char + end_md5) 
                res = requests.get(rawurl, headers=headers, timeout=6, verify=False)
                if start_md5+char+end_md5 in res.content:
                    characterlist.append(char+' ')
                else:
                    characterlist2.append(char+' ')
            cprint("[+]未被过滤的特殊字符: "+''.join(characterlist), "green")
            cprint("[-]被过滤的特殊字符: "+''.join(characterlist2), "red")

            #执行事件驱动 过滤FUZZ

            cprint(">>执行事件驱动FUZZ判断..", "cyan")
            drive_funclist = list()
            drive_funclist2 = list()
            for drive in drive_func:
                drive = drive.strip()
                rawurl = self.url.replace("FUZZING", start_md5 + drive + end_md5)
                res = requests.get(rawurl, headers=headers, timeout=6, verify=False)
                if start_md5+drive+end_md5 in res.content:
                    drive_funclist.append(drive+' ')
                else:
                    drive_funclist2.append(drive+' ')
            cprint("[+]未被过滤的事件驱动: "+''.join(drive_funclist), "green")
            cprint("[-]被过滤的事件驱动: "+''.join(drive_funclist2), "red")
            
            #执行标签 过滤FUZZ
            cprint(">>执行标签FUZZ判断..", "cyan")
            labellist = list()
            labellist2 = list()
            for label in label_func:
                label = label.strip()
                rawurl = self.url.replace("FUZZING", start_md5 + label + end_md5)
                res = requests.get(rawurl, headers=headers, timeout=6, verify=False)
                if start_md5+label+end_md5 in res.content:
                    labellist.append(label+' ')
                else:
                    labellist2.append(label+' ')

            cprint("[+]未被过滤的标签: "+''.join(labellist), "green")
            cprint("[-]被过滤的标签: "+''.join(labellist2), "red")

            #执行标签 过滤FUZZ
            cprint(">>执行弹窗函数FUZZ判断..", "cyan")
            windowlist = list()
            windowlist2 = list()
            for window in window_func:
                window = window.strip()
                rawurl = self.url.replace("FUZZING", start_md5 + window + end_md5)
                res = requests.get(rawurl, headers=headers, timeout=6, verify=False)
                if start_md5+window+end_md5 in res.content:
                    windowlist.append(window+' ')
                else:
                    windowlist2.append(window+' ')

            cprint("[+]未被过滤的弹窗函数: "+''.join(windowlist), "green")
            cprint("[-]被过滤的弹窗函数: "+''.join(windowlist2), "red")
        else:
            cprint("[-]不存在XSS", "green")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = xss_characterfuzz_check_BaseVerify(sys.argv[1])
    testVuln.run()
