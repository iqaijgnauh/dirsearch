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

import urllib.error
import urllib.parse
import urllib.request

from lib.utils.FileUtils import File
from thirdparty.oset import *
from lib.connection.Requester import Dict4Scan, DealMethod


class Dictionary(object):

    def __init__(self, paths, directory, filename, extension, extensions=[], lowercase=False, forcedExtensions=False):
        self.entries = []
        self.directory = directory
        self.filename = filename
        self.extension = extension
        self.currentIndex = 0
        self.condition = threading.Lock()
        self._extensions = extensions
        self._paths = paths
        self._forcedExtensions = forcedExtensions
        self.lowercase = lowercase
        self.dictionaryFiles = [File(path) for path in self.paths]
        self.generate()

    @property
    def extensions(self):
        return self._extensions

    @extensions.setter
    def extensions(self, value):
        self._extensions = value

    @property
    def paths(self):
        return self._paths

    @paths.setter
    def paths(self, paths):
        self._paths = paths

    @classmethod
    def quote(cls, string):
        return urllib.parse.quote(string, safe=":/~?%&+-=$")

    """
    Dictionary.generate() behaviour

    Classic dirsearch wordlist:
      1. If %EXT% keyword is present, append one with each extension REPLACED.
      2. If the special word is no present, append line unmodified.

    Forced extensions wordlist (NEW):
      This type of wordlist processing is a mix between classic processing
      and DirBuster processing.
          1. If %EXT% keyword is present in the line, immediately process as "classic dirsearch" (1).
          2. If the line does not include the special word AND is NOT terminated by a slash,
            append one with each extension APPENDED (line.ext) and ONLYE ONE with a slash.
          3. If the line does not include the special word and IS ALREADY terminated by slash,
            append line unmodified.
    """

    def generate(self):
        result = []
        # Enable to use multiple dictionaries at once
        for dictFile in self.dictionaryFiles:
            if Dict4Scan.logic_dir in dictFile.path:
                dict_deal_method = DealMethod.replace_dir
            else:
                dict_deal_method = DealMethod.extend_dir

            for line in dictFile.getLines():

                # Skip comments
                if line.lstrip().startswith("#"):
                    continue

                # # Classic dirsearch wordlist processing (with %EXT% keyword)
                # if '%EXT%' in line or '%ext%' in line:
                #     for extension in self._extensions:
                #         if '%EXT%' in line:
                #             newline = line.replace('%EXT%', extension)
                #
                #         if '%ext%' in line:
                #             newline = line.replace('%ext%', extension)
                #
                #         quote = self.quote(newline)
                #         result.append(quote)
                #
                # # If forced extensions is used and the path is not a directory ... (terminated by /)
                # # process line like a forced extension.
                # elif self._forcedExtensions and not line.rstrip().endswith("/"):
                #     quoted = self.quote(line)
                #
                #     for extension in self._extensions:
                #         # Why? check https://github.com/maurosoria/dirsearch/issues/70
                #         if extension.strip() == '':
                #             result.append(quoted)
                #         else:
                #             result.append(quoted + '.' + extension)
                #
                #     if quoted.strip() not in ['']:
                #         result.append(quoted + "/")
                #
                # # Append line unmodified.
                # else:
                #     result.append(self.quote(line))

                filename_token = '[Filename]'
                extension_token = '[Extension]'
                directory_token = '[Directory Name]'

                if filename_token in line and self.filename and extension_token in line and self.extension:
                    newline = line.replace(filename_token, self.filename)
                    newline = newline.replace(extension_token, self.extension)
                    result.append((dict_deal_method, self.quote(newline)))
                elif filename_token in line and self.filename:
                    newline = line.replace(filename_token, self.filename)
                    result.append((dict_deal_method, self.quote(newline)))
                elif directory_token in line and self.directory:
                    newline = line.replace(directory_token, self.directory)
                    result.append((dict_deal_method, self.quote(newline)))
                elif filename_token not in line and extension_token not in line and directory_token not in line:
                    result.append((dict_deal_method, self.quote(line)))

        # oset library provides inserted ordered and unique collection.
        if self.lowercase:
            self.entries = list(oset(map(lambda l: l.lower(), result)))

        else:
            self.entries = list(oset(result))

        del (result)

    def regenerate(self):
        self.generate(lowercase=self.lowercase)
        self.reset()

    def nextWithIndex(self, basePath=None):
        self.condition.acquire()

        try:
            result = self.entries[self.currentIndex]

        except IndexError:
            self.condition.release()
            raise StopIteration

        self.currentIndex = self.currentIndex + 1
        currentIndex = self.currentIndex
        self.condition.release()
        return currentIndex, result

    def __next__(self, basePath=None):
        _, path = self.nextWithIndex(basePath)
        return path

    def reset(self):
        self.condition.acquire()
        self.currentIndex = 0
        self.condition.release()

    def __len__(self):
        return len(self.entries)
