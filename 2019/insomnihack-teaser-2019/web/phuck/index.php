<?php
stream_wrapper_unregister('php');
if(isset($_GET['hl'])) highlight_file(__FILE__);

$mkdir = function($dir) {
    system('mkdir -- '.escapeshellarg($dir));
};
$randFolder = bin2hex(random_bytes(16));
$mkdir('users/'.$randFolder);
chdir('users/'.$randFolder);

$userFolder = (isset($_SERVER['HTTP_X_FORWARDED_FOR']) ? $_SERVER['HTTP_X_FORWARDED_FOR'] : $_SERVER['REMOTE_ADDR']);
$userFolder = basename(str_replace(['.','-'],['',''],$userFolder));

$mkdir($userFolder);
chdir($userFolder);
file_put_contents('profile',print_r($_SERVER,true));
chdir('..');
$_GET['page']=str_replace('.','',$_GET['page']);
if(!stripos(file_get_contents($_GET['page']),'<?')
   && !stripos(file_get_contents($_GET['page']),'php')) {
    include($_GET['page']);
}

chdir(__DIR__);
system('rm -rf users/'.$randFolder);
