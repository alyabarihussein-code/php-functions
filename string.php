<?php
echo "<h2>String Functions Practice</h2>";

$text = "Hello PHP World";

// 1- طول النص
echo "النص: $text<br>";
echo "عدد الأحرف: " . strlen($text) . "<br><br>";

// 2- تحويل لحروف كبيرة وصغيرة
echo "Uppercase: " . strtoupper($text) . "<br>";
echo "Lowercase: " . strtolower($text) . "<br><br>";

// 3- أول حرف كبير لكل كلمة
echo "ucfirst: " . ucfirst("php is fun") . "<br>";
echo "ucwords: " . ucwords("php is fun") . "<br><br>";

// 4- استبدال نص
echo "استبدال PHP بـ Programming: " . str_replace("PHP", "Programming", $text) . "<br><br>";

// 5- قص جزء من النص
echo "أول 5 أحرف: " . substr($text, 0, 5) . "<br><br>";

// 6- البحث عن كلمة
echo "موقع كلمة PHP: " . strpos($text, "PHP") . "<br><br>";

// 7- عكس النص
echo "النص معكوس: " . strrev($text) . "<br><br>";

// 8- إزالة المسافات
echo "Trim: '" . trim("   Hello   ") . "'<br><br>";

// 9- تحويل النص إلى مصفوفة
$arr = explode(" ", $text);
echo "Explode:<br>";
print_r($arr);
echo "<br><br>";

// 10- تحويل المصفوفة إلى نص
echo "Implode: " . implode("-", $arr) . "<br><br>";

// 11- تكرار النص
echo "تكرار النص: " . str_repeat("*", 10) . "<br>";

?>
