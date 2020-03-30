# -*- coding: utf-8 -*-
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#
#  Author: Mauro Soria

import http.client
import random
import socket
import time
import urllib.error
import urllib.parse
import urllib.parse
import urllib.request

import thirdparty.requests as requests
from .RequestException import *
from .Response import *
from lib.utils.FileUtils import FileUtils
from difflib import SequenceMatcher


class DealMethod(object):
    replace_dir = 'replace_dir'         # 替换 directory
    extend_dir = 'extend_dir'           # 在 directory 后面添加

class URLType(object):
    normal_file = 'normal_file'       # http://hostname/abc/test.php
    normal_restful_dir = 'normal_restful_dir' # http://hostname/abc/
    restful_file = 'restful_file'     # http://hostname/abc/test

class Dict4Scan(object):
    common_dir = 'dict/common_dir.txt'
    common_file_with_suffix = 'dict/common_file_with_suffix.txt'
    common_file_without_suffix = 'dict/common_file_without_suffix.txt'
    logic_dir = 'dict/logic_dir.txt'
    logic_file = 'dict/logic_file.txt'

    fingerprint = {
        'action': 'dict/fingerprint_action.txt',
        'asp': 'dict/fingerprint_asp.txt',
        'aspx': 'dict/fingerprint_aspx.txt',
        'cgi': 'dict/fingerprint_cgi.txt',
        'do': 'dict/fingerprint_do.txt',
        'jsp': 'dict/fingerprint_jsp.txt',
        'php': 'dict/fingerprint_php.txt',
        'pl': 'dict/fingerprint_pl.txt',
        'py': 'dict/fingerprint_py.txt',
        'rb': 'dict/fingerprint_rb.txt'
    }

class Dict4URLType(object):
    normal_file = [
        Dict4Scan.common_dir,
        Dict4Scan.common_file_with_suffix,
        Dict4Scan.logic_dir,
        Dict4Scan.logic_file
    ]
    normal_restful_dir = [
        Dict4Scan.common_dir,
        Dict4Scan.common_file_with_suffix,
        Dict4Scan.common_file_without_suffix,
        Dict4Scan.logic_dir,
    ]
    restful_file = [
        Dict4Scan.common_dir,
        Dict4Scan.common_file_without_suffix
    ]

class Requester(object):
    headers = {
        'User-agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1468.0 Safari/537.36',
        'Accept-Language': 'en-us',
        'Accept-Encoding': 'identity',
        'Keep-Alive': '300',
        'Connection': 'keep-alive',
        'Cache-Control': 'max-age=0',
    }

    def __init__(self, url, script_path, cookie=None, useragent=None,
                 maxPool=1, maxRetries=5, delay=0, timeout=30,
                 ip=None, proxy=None, redirect=False, requestByHostname=False, httpmethod="get"):

        self.httpmethod = httpmethod
        self.script_path = script_path

        # if no backslash, append one
        # if not url.endswith('/'):
        #     url = url + '/'
        # http://hostname.local add slash
        if urllib.parse.urlparse(url).path == '':
            url = url + '/'

        parsed = urllib.parse.urlparse(url)
        self.basePath = parsed.path

        url_type, suffix, directory_name, filename, base_path = self.getURLTypeAndSuffix(self.basePath)
        self.url_type = url_type
        self.extension = suffix
        self.directory = directory_name
        self.filename = filename
        if base_path:
            self.base_path = base_path
        else:
            self.base_path = '/'
        if self.extension:
            self.site_fingerprint = set([self.extension])
        else:
            self.site_fingerprint = set([])

        if self.url_type == URLType.normal_file:
            self.scan_dict = Dict4URLType.normal_file
        elif self.url_type == URLType.normal_restful_dir:
            self.scan_dict = Dict4URLType.normal_restful_dir
        elif self.url_type == URLType.restful_file:
            self.scan_dict = Dict4URLType.restful_file

        # if not protocol specified, set http by default
        if parsed.scheme != 'http' and parsed.scheme != 'https':
            parsed = urllib.parse.urlparse('http://' + url)
            self.basePath = parsed.path

        self.protocol = parsed.scheme

        if self.protocol != 'http' and self.protocol != 'https':
            self.protocol = 'http'

        self.host = parsed.netloc.split(':')[0]

        # resolve DNS to decrease overhead
        if ip is not None:
            self.ip = ip
        else:
            try:
                self.ip = socket.gethostbyname(self.host)
            except socket.gaierror:
                raise RequestException({'message': "Couldn't resolve DNS"})

        self.headers['Host'] = self.host

        # If no port specified, set default (80, 443)
        try:
            self.port = parsed.netloc.split(':')[1]
        except IndexError:
            self.port = (443 if self.protocol == 'https' else 80)

        # Set cookie and user-agent headers
        if cookie is not None:
            self.setHeader('Cookie', cookie)

        if useragent is not None:
            self.setHeader('User-agent', useragent)

        self.maxRetries = maxRetries
        self.maxPool = maxPool
        self.delay = delay
        self.timeout = timeout
        self.pool = None
        self.proxy = proxy
        self.redirect = redirect
        self.randomAgents = None
        self.requestByHostname = requestByHostname
        self.session = requests.Session()

    def getURLTypeAndSuffix(self, path):
        suffix = None
        directory_name, _file = path.rsplit('/', 2)[-2:]
        if '.' in _file:
            filename, suffix = _file.rsplit('.', 1)
        else:
            filename = _file

        if filename and suffix:
            _ = ''.join(path.rsplit('.{}'.format(suffix), 1))
            _ = ''.join(_.rsplit(filename, 1))
            base_path = ''.join(_.rsplit('{}/'.format(directory_name), 1))
            return URLType.normal_file, suffix, directory_name, filename, base_path
        elif filename:
            _ = ''.join(path.rsplit(filename, 1))
            base_path = ''.join(_.rsplit('{}/'.format(directory_name), 1))
            return URLType.restful_file, '', directory_name, filename, base_path
        else:
            base_path = ''.join(path.rsplit('{}/'.format(directory_name), 1))
            return URLType.normal_restful_dir, '', directory_name, '', base_path

    @property
    def scan_list(self):
        scan_list = []
        scan_list.extend([FileUtils.buildPath(self.script_path, "", _) for _ in self.scan_dict])
        for _fp in list(self.site_fingerprint):
            _ = Dict4Scan.fingerprint.get(_fp)
            if _:
                scan_list.append(FileUtils.buildPath(self.script_path, "", _))
        return scan_list

    def setHeader(self, header, content):
        self.headers[header] = content

    def setRandomAgents(self, agents):
        self.randomAgents = list(agents)

    def unsetRandomAgents(self):
        self.randomAgents = None

    def waf_detect(self, site_index_response, url_quote):
        waf_exist = False
        waf_path_str = "{}?testparam=1234 AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert(\"XSS\")</script>',table_name FROM information_schema.tables WHERE 2>1--/**/; EXEC xp_cmdshell('cat ../../../etc/passwd')#".format(
            self.basePath)
        waf_path = url_quote(waf_path_str)
        waf_response = self.request(waf_path, use_base_path=False)
        if SequenceMatcher(None, site_index_response, waf_response.body).quick_ratio() < 0.6:
            waf_exist = True
        return waf_exist, waf_response

    def request(self, path, use_base_path=True, allow_redirect=False, fingerprint=False):
        i = 0
        proxy = None
        result = None
        self.redirect = allow_redirect

        while i <= self.maxRetries:

            try:
                if self.proxy is not None:
                    proxy = {"https": self.proxy, "http": self.proxy}

                # 请求ip，并将headers的host字段设置为netloc即可
                if self.requestByHostname:
                    url = "{0}://{1}:{2}".format(self.protocol, self.host, self.port)

                else:
                    url = "{0}://{1}:{2}".format(self.protocol, self.ip, self.port)


                if use_base_path:
                    url = urllib.parse.urljoin(url, self.basePath)

                    # Joining with concatenation because a urljoin bug with "::"
                    if not url.endswith('/'):
                        url += "/"

                    if path.startswith('/'):
                        path = path[1:]

                url += path



                headers = dict(self.headers)
                if self.randomAgents is not None:
                    headers["User-agent"] = random.choice(self.randomAgents)

                headers["Host"] = self.host

                # include port in Host header if it's non-standard
                if (self.protocol == "https" and self.port != 443) or \
                        (self.protocol == "http" and self.port != 80):
                    headers["Host"] += ":{0}".format(self.port)

                if (self.httpmethod == "get"):
                    response = self.session.get(
                        url,
                        proxies=proxy,
                        verify=False,
                        allow_redirects=self.redirect,
                        headers=headers,
                        timeout=self.timeout
                    )

                if (self.httpmethod == "head"):
                    response = self.session.head(
                        url,
                        proxies=proxy,
                        verify=False,
                        allow_redirects=self.redirect,
                        headers=headers,
                        timeout=self.timeout
                    )

                if (self.httpmethod == "post"):
                    response = self.session.post(
                        url,
                        proxies=proxy,
                        verify=False,
                        allow_redirects=self.redirect,
                        headers=headers,
                        timeout=self.timeout
                    )

                result = Response(response.status_code, response.reason, response.headers, response.content, )
                if fingerprint:
                    # TODO: ident fingerprints from response headers
                    self.site_fingerprint.update(result.get_suffixes(origin=self.host))
                time.sleep(self.delay)
                del headers
                break

            except requests.exceptions.TooManyRedirects as e:
                raise RequestException({'message': 'Too many redirects: {0}'.format(e)})

            except requests.exceptions.SSLError:
                raise RequestException(
                    {'message': 'SSL Error connecting to server. Try the -b flag to connect by hostname'})

            except requests.exceptions.ConnectionError as e:
                if self.proxy is not None:
                    raise RequestException({'message': 'Error with the proxy: {0}'.format(e)})
                continue

            except (requests.exceptions.ConnectTimeout,
                    requests.exceptions.ReadTimeout,
                    requests.exceptions.Timeout,
                    http.client.IncompleteRead,
                    socket.timeout):
                continue

            finally:
                i = i + 1

        if i > self.maxRetries:
            raise RequestException(
                {'message': 'CONNECTION TIMEOUT: There was a problem in the request to: {0}'.format(path)}
            )

        return result
