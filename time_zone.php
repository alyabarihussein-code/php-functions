<?php
// الحصول على المنطقة الزمنية الافتراضية
echo "المنطقة الزمنية الافتراضية: " . date_default_timezone_get() . "<br>";

// تغيير المنطقة الزمنية
date_default_timezone_set("Europe/London");
echo "الوقت في لندن: " . date("Y-m-d H:i:s") . "<br>";

// منطقة ثانية
date_default_timezone_set("America/New_York");
echo "الوقت في نيويورك: " . date("Y-m-d H:i:s");
?>
