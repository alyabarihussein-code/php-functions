<?php
echo "<h2>Array Functions Practice</h2>";

// مصفوفة أرقام
$numbers = [10, 20, 30];
echo "المصفوفة الأصلية:<br>";
print_r($numbers);
echo "<br><br>";

// 1- عدد العناصر
echo "عدد العناصر: " . count($numbers) . "<br><br>";

// 2- إضافة عنصر في النهاية
array_push($numbers, 40);
echo "بعد الإضافة:<br>";
print_r($numbers);
echo "<br><br>";

// 3- حذف آخر عنصر
array_pop($numbers);
echo "بعد حذف آخر عنصر:<br>";
print_r($numbers);
echo "<br><br>";

// 4- إضافة عنصر في البداية
array_unshift($numbers, 5);
echo "بعد إضافة عنصر في البداية:<br>";
print_r($numbers);
echo "<br><br>";

// 5- حذف أول عنصر
array_shift($numbers);
echo "بعد حذف أول عنصر:<br>";
print_r($numbers);
echo "<br><br>";

// 6- عكس ترتيب العناصر
echo "المصفوفة معكوسة:<br>";
print_r(array_reverse($numbers));
echo "<br><br>";

// 7- التحقق من وجود قيمة
if (in_array(20, $numbers)) {
    echo "20 موجودة في المصفوفة<br>";
}

// 8- دمج مصفوفتين
$names = ["Ali", "Sara"];
$merged = array_merge($numbers, $names);
echo "بعد دمج الأسماء مع الأرقام:<br>";
print_r($merged);
echo "<br><br>";

// 9- حذف القيم المكررة
$dup = [1,1,2,2,3];
echo "بعد حذف القيم المكررة:<br>";
print_r(array_unique($dup));
echo "<br>";
?>
