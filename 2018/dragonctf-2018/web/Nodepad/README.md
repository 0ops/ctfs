# Nodepad

This is a typical XSS challenge, after looking at source code, we will know flag can be fetched from ``/admin/flag``.

```javascript
router.get('/flag', (req, res) => {
  res.render('index', {notices: [process.env.FLAG]});
});
```

## RexExp Bypass

Obviously, the vulnerable part in the application is adding notes, but we can not inject ``<>`` here.

```javascript
const regex = /[<>]/;

let errors = [];
if (regex.test(req.body.title)) {
errors.push('Title is invalid');
}

if (regex.test(req.body.content)) {
errors.push('Content is invalid');
}

if (errors.length !== 0) {
return res.render('new', {errors});
}
```

To bypass this regexp, we can use a little trick here:

```javascript
regex.test(['a' : '<']) // true
regex.test({'a' : '<'}) // false
```

So if we post a dict, we can insert any tag we want. There is one thing which we need pay attention is we can not post dict with ``application/x-www-form-urlencoded`` in express, so we can should use ``application/json`` here.

## CSP Bypass

We can inject any tag now, but there has a CSP which we need bypass:

```
default-src 'none';
script-src 'nonce-43fa45e17bdab68f0714216de52b1a08' 'strict-dynamic';
style-src 'self' https://stackpath.bootstrapcdn.com/bootstrap/4.1.3/css/bootstrap.min.css;
img-src 'self';
connect-src 'self';
frame-src https://www.google.com/recaptcha/;
form-action 'self';
```

This part is easy, we could use ``<base>`` tag then admin will request ``/javascripts/notes.js`` from our server.

## Final Part

After writing a script to get flag, I found there is only a request to get ``/javascripts/notes.js``, no flag. Check the request for some time, I found the ``Refer`` is ``http://10.62.20.153:3000``, so we can't get flag by ``http://nodepad.hackable.software:3000``, we need request ``http://10.62.20.153:3000/admin/flag`` here.

Finally, flag is ``DrgnS{Ar3_Y0u_T3mP14t3d?}``.

You can see my [script](https://github.com/0ops/ctfs/blob/master/2018/dragonctf-2018/web/Nodepad/cli.py) and [notes.js](https://github.com/0ops/ctfs/blob/master/2018/dragonctf-2018/web/Nodepad/notes.js) in this repo.
