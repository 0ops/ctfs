<!-- 

/* * *  Power By 0xd0ff9 * * * 

--> 
<?php 
include "config.php"; 
if(isset($_GET['debug'])) 
{ 
    show_source(__FILE__); 
    die("..."); 
} 
?> 
<!DOCTYPE html> 
<html lang="en"> 
<head> 
  <title>The Two piece Treasure</title> 
  <meta charset="utf-8"> 
  <meta name="viewport" content="width=device-width, initial-scale=1"> 
  <!-- Latest compiled and minified CSS --> 
  <link rel="stylesheet" href="css/bootstrap.min.css"> 

  <!-- jQuery library --> 
  <script src="js/jquery.min.js"></script> 

  <!-- Latest compiled JavaScript --> 
  <script src="js/bootstrap.min.js"></script> 
</head> 
<body> 

<?php 



$grandline = $_SERVER['REQUEST_URI']; 
// Best Grandline is short 
$grandline = substr($grandline,0,500); 

echo "<!-- P/s: Your grand line is ".htmlentities(urldecode($grandline),ENT_QUOTES)." , this is not Luffy 's grand line -->"; 


?> 

<div class="container"> 
<div class="jumbotron"> 
    <h1>GRAND LINE</h1>  
    <p>Welcome to Grand Line, You are in the way to become Pirate King, now, let's defeat <a href="bot.php">BigMom</a> first</p>  
</div> 
<?php 

$loca = $_SERVER["REMOTE_ADDR"]; 

echo "<input name='location' value='".$loca."' type='hidden'><br>"; 
if ($loca === "127.0.0.1" || $loca==="::1") 
{ 
    echo "<input name='piece' value='".$secret."' type='hidden'>"; 
} 
else 
{ 
    echo "<input name='piece' value='Only whitebeard can see it, Gura gura gura' type='hidden'>"; 
} 

?> 

  <h4>If you eat fruit, you can't swim</h4> 
        <img src="images/grandline.png"/> 
        <br> 
        <form method="get" action="index.php"> 
        <input type="text" name="eat" placeholder="" value="gomu gomu no mi">         
        <input type="submit"> 
        </form> 
    <?php  
    if(isset($_GET['eat'])&&!empty($_GET['eat'])) 
    { 
        if($_GET['eat'] === "gomu gomu no mi") 
        { 
            echo "<p>Pirate, Let's go to your Grand Line</p>"; 
        } 
        else 
        { 
            echo "<p>You need to eat 'gomu gomu no mi'</p>"; 
        } 
    } 
     
    ?> 
</div> 


</body> 
</html> 

















































<!-- Infact, ?debug will help you learn expression to build Grand Line ( Ex: !<>+-*/ ) 
