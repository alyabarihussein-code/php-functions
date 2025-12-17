<?php
// التعامل مع الملفات
$filename = "test.txt";


file_put_contents($filename, "صباحوووووووووو \n");

echo file_get_contents($filename);

file_put_contents($filename, "هاذا سطر جديد\n", FILE_APPEND);


echo "<br>" . file_get_contents($filename); 


?>
