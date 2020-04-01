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

import threading

from lib.connection.RequestException import RequestException
from .Path import *
from .Scanner import *
from difflib import SequenceMatcher
import random
from lib.utils import RandomUtils
from lib.connection.Requester import DealMethod

class Fuzzer(object):
    def __init__(self, requester, dictionary, waf_exist, waf_response, response_404, testFailPath=None, threads=1, matchCallbacks=[], notFoundCallbacks=[],
                 errorCallbacks=[]):

        self.requester = requester
        self.dictionary = dictionary
        self.testFailPath = testFailPath
        self.basePath = self.requester.basePath
        self.threads = []
        self.threadsCount = threads if len(self.dictionary) >= threads else len(self.dictionary)
        self.running = False
        self.scanners = {}
        self.defaultScanner = None
        self.matchCallbacks = matchCallbacks
        self.notFoundCallbacks = notFoundCallbacks
        self.errorCallbacks = errorCallbacks
        self.matches = []
        self.errors = []
        self.waf_exist = waf_exist
        self.waf_response = waf_response
        self.response_404 = response_404

    def wait(self, timeout=None):
        for thread in self.threads:
            thread.join(timeout)

            if timeout is not None and thread.is_alive():
                return False

        return True

    def setupScanners(self):
        '''404 页面，网站页面内容动态性探测'''
        if len(self.scanners) != 0:
            self.scanners = {}

        self.defaultScanner = Scanner(self.requester, self.testFailPath, "")
        self.scanners['/'] = Scanner(self.requester, self.testFailPath, "/")

        for extension in self.dictionary.extensions:
            self.scanners[extension] = Scanner(self.requester, self.testFailPath, "." + extension)

    def setupThreads(self):
        if len(self.threads) != 0:
            self.threads = []

        for thread in range(self.threadsCount):
            # thread_proc 为实际运行爆破函数
            newThread = threading.Thread(target=self.thread_proc)
            newThread.daemon = True
            self.threads.append(newThread)

    def getScannerFor(self, path):
        if path.endswith('/'):
            return self.scanners['/']

        for extension in list(self.scanners.keys()):
            if path.endswith(extension):
                return self.scanners[extension]

        # By default, returns empty tester
        return self.defaultScanner

    def start(self):
        # Setting up testers
        # 404 页面，302跳转location字段动态性探测
        self.setupScanners()
        # Setting up threads
        self.setupThreads()
        self.index = 0
        self.dictionary.reset()
        self.runningThreadsCount = len(self.threads)
        self.running = True
        self.playEvent = threading.Event()
        self.pausedSemaphore = threading.Semaphore(0)
        self.playEvent.clear()
        self.exit = False

        for thread in self.threads:
            thread.start()

        self.play()

    def play(self):
        self.playEvent.set()

    def pause(self):
        self.playEvent.clear()
        for thread in self.threads:
            if thread.is_alive():
                self.pausedSemaphore.acquire()

    def stop(self):
        self.running = False
        self.play()

    def scan(self, path):
        '''多线程发包逻辑'''
        response = self.requester.request(path, use_base_path=False)
        result = None
        ratio_bound = 0.7

        ## default logic
        # if self.getScannerFor(path).scan(path, response):
            # 文件存在性判断逻辑
        result = (None if response.status == 404 else response.status)

        # 404页面对比
        # if not self.getScannerFor(path).scan(path, response):
        #     return result, response
        if SequenceMatcher(None, response.body, self.response_404.body).quick_ratio() > ratio_bound:
            return result, response
        # WAF
        if self.waf_exist and SequenceMatcher(None, response.body, self.waf_response.body).quick_ratio() > ratio_bound:
            return result, response

        # special page detect
        # filename and extension with two request, filename(no ext) and dir with one request
        special_path = self.get_special_path(path)
        for _ in special_path:
            _special_path = self.dictionary.quote(_)
            special_response = self.requester.request(_special_path, use_base_path=False)
            if SequenceMatcher(None, response.body, special_response.body).quick_ratio() > ratio_bound:
                return result, response
        return result, response

    def get_special_path(self, path):
        special_path = []
        if path.endswith('/'):
            _origin_path, _dir = path[:-1].rsplit('/', 1)
        else:
            _origin_path, _last_element = path.rsplit('/', 1)

        if path.endswith('/'):
            # unzip exception
            _origin_path, _dir = path[:-1].rsplit('/', 1)
            special_dir = self.get_special_str(_dir)
            _path = '{}/{}/'.format(_origin_path, special_dir)
            if not _path.startswith('/'):
                _path = '/' + _path
            special_path.append(_path)
        elif '.' in _last_element:
            _origin_path, _filename_ext = path.rsplit('/', 1)
            _filename, _ext = _filename_ext.rsplit('.', 1)
            # special filename
            if not _filename:
                _filename = RandomUtils.randString(n=8)
            special_filename = self.get_special_str(_filename)
            _path = '{}/{}.{}'.format(_origin_path, special_filename, _ext)
            if not _path.startswith('/'):
                _path = '/' + _path
            special_path.append(_path)
            # special extension
            if not _ext:
                _ext = RandomUtils.randString(n=8)
            special_extension = self.get_special_str(_ext)
            _path = '{}/{}.{}'.format(_origin_path, _filename, special_extension)
            if not _path.startswith('/'):
                _path = '/' + _path
            special_path.append(_path)
        else:
            _origin_path, _filename = path.rsplit('/', 1)
            special_filename = self.get_special_str(_filename)
            _path = '{}/{}'.format(_origin_path, special_filename)
            if not _path.startswith('/'):
                _path = '/' + _path
            special_path.append(_path)
        return special_path

    def get_special_str(self, str):
        str_list = list(str)
        str_set_len = len(set(str_list))

        for _ in range(100):
            if str_set_len == 1 and len(str_list) == 1:
                new_str = RandomUtils.randString(n=1, omit=str_list)
            elif str_set_len == 1:
                _ = RandomUtils.randString(n=len(str_list)-str_set_len)
                new_str = '{}{}'.format(str_list[0], _)
            else:
                random.shuffle(str_list)
                new_str = ''.join(str_list)
            if new_str == str:
                continue
            return new_str
        else:
            raise Exception('Special Str: {}'.format(str))

    def isRunning(self):
        return self.running

    def finishThreads(self):
        self.running = False
        self.finishedEvent.set()

    def isFinished(self):
        return self.runningThreadsCount == 0

    def stopThread(self):
        self.runningThreadsCount -= 1

    def thread_proc(self):
        '''多线程发包'''
        self.playEvent.wait()
        try:
            deal_method, path = next(self.dictionary)
            while path is not None:
                try:
                    # if path is file, replace filename.ext, filename, directory
                    # elif path is directory remove filename.ext, filename, both add and replace directory
                    # dir replace
                    if path.endswith('/') and deal_method == DealMethod.replace_dir:
                        if self.requester.directory:
                            path = '{}{}'.format(self.requester.base_path, path)
                        else:
                            deal_method, path = next(self.dictionary)
                            continue
                    # elif source_dict == 'logic_dict':
                    #     if self.requester.filename:
                    #         path = '{}{}/{}'.format(self.requester.base_path, self.requester.directory, path)
                    #     else:
                    #         path = '{}{}'.format(self.requester.base_path, path)
                    # dir add, file add
                    else:
                        if self.requester.directory:
                            path = '{}{}/{}'.format(self.requester.base_path, self.requester.directory, path)
                        else:
                            path = '{}{}'.format(self.requester.base_path, path)
                    status, response = self.scan(path)
                    result = Path(path=path, status=status, response=response)

                    if status is not None:
                        self.matches.append(result)
                        for callback in self.matchCallbacks:
                            callback(result)
                    else:
                        for callback in self.notFoundCallbacks:
                            callback(result)
                    del status
                    del response

                except RequestException as e:

                    for callback in self.errorCallbacks:
                        callback(path, e.args[0]['message'])

                    continue

                finally:
                    if not self.playEvent.isSet():
                        self.pausedSemaphore.release()
                        self.playEvent.wait()

                    source_dict, path = next(self.dictionary)  # Raises StopIteration when finishes

                    if not self.running:
                        break

        except StopIteration:
            return

        finally:
            self.stopThread()
