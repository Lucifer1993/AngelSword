#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: system漏洞库
referer: unknow
author: Lucifer
description: 包含所有system漏洞类型，封装成一个模块
'''
#couchdb vulns
from system.couchdb.couchdb_unauth import couchdb_unauth_BaseVerify

#zookeeper vulns
from system.zookeeper.zookeeper_unauth import zookeeper_unauth_BaseVerify

#GoAhead vulns
from system.goahead.goahead_LD_PRELOAD_rce import goahead_LD_PRELOAD_rce_BaseVerify

#topsec vulns
from system.topsec.topsec_change_lan_filedownload import topsec_change_lan_filedownload_BaseVerify

#tomcat vulns
from system.tomcat.tomcat_weak_pass import tomcat_weak_pass_BaseVerify
from system.tomcat.tomcat_put_exec import tomcat_put_exec_BaseVerify

#redis vulns
from system.redis.redis_unauth import redis_unauth_BaseVerify

#kinggate vulns
from system.kinggate.kinggate_zebra_conf import kinggate_zebra_conf_BaseVerify

#nginx vulns
from system.nginx.multi_fastcgi_code_exec import multi_fastcgi_code_exec_BaseVerify

#turbomail vulns
from system.turbomail.turbomail_conf import turbomail_conf_BaseVerify
from system.turbomail.turbogate_services_xxe import turbogate_services_xxe_BaseVerify

#weblogic vulns
from system.weblogic.weblogic_weak_pass import weblogic_weak_pass_BaseVerify
from system.weblogic.weblogic_ssrf import weblogic_ssrf_BaseVerify
from system.weblogic.weblogic_xmldecoder_exec import weblogic_xmldecoder_exec_BaseVerify
from system.weblogic.weblogic_interface_disclosure import weblogic_interface_disclosure_BaseVerify

#hudson vulns
from system.hudson.hudson_ws_disclosure import hudson_ws_disclosure_BaseVerify

#vhost vulns
from system.vhost.npoint_mdb_download import npoint_mdb_download_BaseVerify
from system.vhost.zkeys_database_conf import zkeys_database_conf_BaseVerify
from system.vhost.hac_gateway_info_disclosure import hac_gateway_info_disclosure_BaseVerify

#others vulns
from system.others.forease_fileinclude_code_exec import forease_fileinclude_code_exec_BaseVerify
from system.others.moxa_oncell_telnet import moxa_oncell_telnet_BaseVerify

#glassfish vulns
from system.glassfish.glassfish_fileread import glassfish_fileread_BaseVerify

#zabbix vulns
from system.zabbix.zabbix_jsrpc_profileIdx2_sqli import zabbix_jsrpc_profileIdx2_sqli_BaseVerify

#php vulns
from system.php.php_expose_disclosure import php_expose_disclosure_BaseVerify
from system.php.php_fastcgi_read import php_fastcgi_read_BaseVerify

#hfs vulns
from system.hfs.hfs_rejetto_search_rce import hfs_rejetto_search_rce_BaseVerify

#bash vulns
from system.bash.shellshock import shellshock_BaseVerify

#dorado vulns
from system.dorado.dorado_default_passwd import dorado_default_passwd_BaseVerify

#iis vulns
from system.iis.iis_ms15034_httpsys_rce import iis_ms15034_httpsys_rce_BaseVerify
from system.iis.iis_webdav_rce import iis_webdav_rce_BaseVerify

#srun vulns
from system.srun.srun_index_file_filedownload import srun_index_file_filedownload_BaseVerify
from system.srun.srun_rad_online_bypass_rce import srun_rad_online_bypass_rce_BaseVerify
from system.srun.srun_rad_online_username_rce import srun_rad_online_username_rce_BaseVerify
from system.srun.srun_download_file_filedownload import srun_download_file_filedownload_BaseVerify
from system.srun.srun_user_info_uid_rce import srun_user_info_uid_rce_BaseVerify 

#intel vulns
from system.intel.intel_amt_crypt_bypass import intel_amt_crypt_bypass_BaseVerify

#smtp vulns
from system.smtp.smtp_starttls_plaintext_inj import smtp_starttls_plaintext_inj_BaseVerify

#resin vulns
from system.resin.resin_viewfile_fileread import resin_viewfile_fileread_BaseVerify

#mongodb vulns
from system.mongodb.mongodb_unauth import mongodb_unauth_BaseVerify

#sangfor vulns
from system.sangfor.sangfor_ad_script_command_exec import sangfor_ad_script_command_exec_BaseVerify