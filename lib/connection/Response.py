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


class Response(object):

    def __init__(self, status, reason, headers, body):
        self.status = status
        self.reason = reason
        self.headers = headers
        self.body = body

    def __str__(self):
        return self.body

    def __int__(self):
        return self.status

    def __eq__(self, other):
        return self.status == other.status and self.body == other.body

    def __cmp__(self, other):
        return (self.body > other) - (self.body < other)

    def __len__(self):
        return len(self.body)

    def __hash__(self):
        return hash(self.body)

    def __del__(self):
        del self.body
        del self.headers
        del self.status
        del self.reason

    @property
    def redirect(self):
        headers = dict((key.lower(), value) for key, value in self.headers.items())
        return headers.get("location")

    @property
    def pretty(self):
        try:
            from bs4 import BeautifulSoup
        except ImportError:
            raise Exception('BeautifulSoup must be installed to get pretty HTML =(')
        html = BeautifulSoup(self.body, 'html.parser')
        return html.prettify()

    def get_suffixes(self, origin):
        try:
            from bs4 import BeautifulSoup
            from urllib.parse import urlparse
        except ImportError:
            raise Exception('BeautifulSoup must be installed to get pretty HTML =(')
        html = BeautifulSoup(self.body, 'html.parser')
        # return html.prettify()
        _suffix = []
        for tag_a in html.find_all('a'):
            link = tag_a.get('href') or '/'
            if link.startswith('http'):
                _ = urlparse(link)
                # 不同源url不考虑后缀
                if origin not in _.netloc:
                    continue
                link = _.path
            last_element = link.split('/')[-1]
            suffix = last_element.split('.')[-1]
            if suffix:
                _suffix.append(suffix)
        return set(_suffix)