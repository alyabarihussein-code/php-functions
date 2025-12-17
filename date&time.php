<?php
// تحديد المنطقة الزمنية
date_default_timezone_set("Asia/Riyadh");

// التاريخ والوقت الحالي
echo "التاريخ والوقت الآن: " . date("Y-m-d H:i:s") . "<br>";

// تحويل نص إلى timestamp
$time = strtotime("2025-12-25 10:00:00");
echo "Timestamp ل 25 ديسمبر 2025: " . $time . "<br>";

// استخدام mktime
$custom_time = mktime(15, 30, 0, 12, 25, 2025);
echo "التاريخ والوقت المخصص: " . date("Y-m-d H:i:s", $custom_time);
?>
