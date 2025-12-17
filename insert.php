<?php
include 'connect.php'; 
 "<br>";

$username = "ali";
$email = "ali@example.com";


$sql = "INSERT INTO users (username, email) VALUES ('$username', '$email')";

if ($conn->query($sql) === TRUE) {
    echo "تم إضافة المستخدم بنجاح";
} else {
    echo "خطأ: " . $conn->error;
}

$conn->close();
?>
