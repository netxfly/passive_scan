# -*- coding: utf-8 -*-
__author__ = 'haifeng11'

"""
调用arachni客户端的扫描
"""

import os
import time
import hashlib
import threading
import subprocess
from urlparse import urlparse

from arachni_config import *

# Arachni rpc clint scan class
class Arachni_Console(object):
    def __init__(self, url, http_agent="xsec", cookies="", page_limit=1):
        self.start_time         = str(time.time())
        # self.dispatcher_url     = "--dispatcher-url=%s" % dispatcher_url
        self.url                = url
        self.report             = "%s_%s" % (urlparse(url).netloc, hashlib.md5(self.start_time).hexdigest())
        self.limit              = page_limit
        self.page_limit         = "--scope-page-limit=%s" % self.limit
        self.report_file        =  "--report-save-path=/tmp/%s.afr" % self.report
        self.http_agent         = http_agent
        self.cookies            = cookies
        self.audit = "--audit-links --audit-forms --audit-cookies"
        self.h_agent = "--http-user-agent='%s'" % (self.http_agent)
        self.h_cookies = "--http-cookie-string='%s'" % (self.cookies)
        self.checks = "--checks=sql_injection,rfi,directory_listing"
        # self.checks = "--checks=rfi,directory_listing,sql_injection,sql_injection_timing,sql_injection_differential,source_code_disclosure,file_inclusion"
        self.timeout = "--timeout=%s" % "2:30:00"
        self.arachni_client = ARACHNI_CLIENT
        self.arachni_reporter = ARACHNI_REPORTER
        self.is_timeout = False
        self.proc       = None
        self.report_jsfile  = '/tmp/%s.json' % self.report
        self.result = None

    # Start to Scan
    def _Scan(self):
        # subprocess command
        self.cmd = [
            self.arachni_client,
            self.h_agent,
            # self.h_cookies,
            # self.audit,
            self.checks,
            self.page_limit,
            self.timeout,
            self.report_file,
            # self.dispatcher_url,
            self.url
        ]

        if self.cookies:
            self.cmd.insert(2, self.h_cookies)

        if self.limit:
            self.cmd.insert(3, self.page_limit)

        print self.cmd
        self.timer = threading.Timer(60 * 10, self.set_time_out())
        self.timer.start()

        self.proc = subprocess.Popen(self.cmd)

        self.proc.wait()
        self.timer.cancel()
        print self.proc.poll()
        print self.proc.pid

    # timeout function
    def set_time_out(self):
        if self.proc is not None:
            self.is_timeout = True
            self.timer.cancel()
            self.proc.kill()


    def get_report(self):
        # arachni_reporter /tmp/test.afr --report=json:outfile=/tmp/test.json
        try:
            self._Scan()
            self._report()
        except Exception, e:
            pass
            # raise e

        return self.result

    # get result, format is json
    def _report(self):
        self.cmd = [
            self.arachni_reporter,
            "/tmp/%s.afr" % self.report,
            '--report=json:outfile=%s' % self.report_jsfile
        ]
        print self.cmd
        self.proc = subprocess.Popen(self.cmd)
        self.proc.wait()
        print self.report_jsfile
        self.result = open(self.report_jsfile).read()
        # del report files
        os.remove(self.report)
        os.remove(self.report_jsfile)

# Main function
if __name__ == '__main__':
    dispatcher_url = "127.0.0.1:7331"
    all_domains = dict()
    domains = [
        "http://www.weibo.com",
        "http://www.sina.com.cn"
    ]

    for domain in domains:
        arachni_console = Arachni_Console(domain, http_agent='Sinasec')
        result = arachni_console.get_report()
        print result