<?php

$host = "localhost";  
$user = "root";    
$pass = "";           
$db   = "mydatabase"; 


$conn = new mysqli($host, $user, $pass, $db);


if ($conn->connect_error) {
    die("فشل الاتصال: " . $conn->connect_error);
}

echo "تم الاتصال بقاعدة البيانات بنجاح!";
?>
