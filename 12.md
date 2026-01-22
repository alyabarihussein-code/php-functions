# 
## مع أمثلة عملية

---

### **1. لماذا SSRF أخطر من XSS؟**
- **SSRF**: Server-Side Request Forgery - يجبر الخادم على طلب موارد داخلية.
- **الخطر**: لأنه يصل للشبكة الداخلية التي لا يصل لها المهاجم عادةً.
- **المقارنة**:
  - **XSS**: يؤثر على متصفحات المستخدمين.
  - **SSRF**: يؤثر على الخادم والشبكة الداخلية.
- **المثال**:  
  ```
  GET /fetch?url=http://localhost/admin
  GET /fetch?url=file:///etc/passwd
  GET /fetch?url=http://169.254.169.254/latest/meta-data/
  ```

---

### **2. لماذا الخادم هدف؟**
- **الأسباب**:
  1. **بيانات حساسة**: قواعد البيانات، ملفات التكوين.
  2. **صلاحيات أعلى**: يمكن تنفيذ أوامر نظام.
  3. **اتصالات داخلية**: مع خدمات أخرى في الشبكة الداخلية.
  4. **ثقة متبادلة**: الخدمات الداخلية تثق ببعضها.
- **النتيجة**: اختراق خادم واحد قد يعني اختراق الشبكة بالكامل.

---

### **3. كيف تُستغل Metadata؟**
- **في السحابة**: Metadata services (مثل AWS، Azure، GCP).
- **المثال (AWS)**:  
  ```
  http://169.254.169.254/latest/meta-data/
  http://169.254.169.254/latest/user-data/
  http://169.254.169.254/latest/identity-credentials/
  ```
- **البيانات المسروقة**: API keys، SSH keys، بيانات التكوين.

---

### **4. لماذا DNS خطر؟**
- **DNS Rebinding Attack**: تغيير عنوان IP أثناء الجلسة.
- **الهجوم**:
  1. المهاجم يتحكم بـ DNS خاص.
  2. الخادم يحل اسم النطاق → IP خارجي (للتحقق).
  3. أثناء الطلب، DNS يعطي → IP داخلي (127.0.0.1).
  4. الخادم يطلب من العنوان الداخلي.
- **النتيجة**: تجاوز الـ whitelist.

---

### **5. كيف يؤدي Redirect لتصيّد؟**
- **Open Redirect**: تحويل المستخدم لموقع خبيث.
- **المثال**:  
  ```
  https://victim.com/login?redirect=https://evil.com
  ```
- **الاستغلال**:
  1. رابط يبدو شرعياً: `https://victim.com/go?url=https://evil.com`
  2. المستخدم يثق (لأنه يبدأ بـ victim.com).
  3. يتم التحويل لـ evil.com.
  4. هجوم Phishing.

---

### **6. لماذا API تحتاج تحقق إضافي؟**
- **الفرق عن صفحات الويب**:
  1. **لا cookies تلقائياً**: تحتاج tokens.
  2. **Rate Limiting أساسي**: لمنع Abuse.
  3. **إصدارات**: Versioning مهم.
  4. **توثيق**: يجب أن يكون واضحاً.
- **الحماية**: API Keys، OAuth 2.0، JWT.

---

### **7. ما الفرق بين Auth و AuthZ؟**
| **Authentication (Auth)** | **Authorization (AuthZ)** |
|--------------------------|--------------------------|
| من أنت؟ | ماذا يُسمح لك؟ |
| إثبات الهوية | تحديد الصلاحيات |
| مثال: تسجيل دخول | مثال: هل يمكنك حذف هذا المستخدم؟ |
| أدوات: كلمة مرور، MFA | أدوات: RBAC، ACL |
- **الترتيب**: Authentication أولاً، ثم Authorization.

---

### **8. لماذا Mass Assignment خطير؟**
- **المشكلة**: السماح للمستخدم بتحديث جميع الحقول، حتى الحساسة.
- **المثال (في Laravel)**:  
  ```php
  // خطأ
  $user->update($request->all());
  
  // المستخدم يرسل:
  {
    "name": "new name",
    "role": "admin",  // غير مصرح!
    "balance": 10000  // خطير!
  }
  ```
- **الحل**: `$fillable` أو `$guarded`.

---

### **9. كيف يمنع Rate Limiting الاستغلال؟**
- **يحمي من**:
  1. **Brute Force**: محاولات تخمين كلمات المرور.
  2. **DoS**: إغراق الخادم بطلبات.
  3. **API Abuse**: استخدام غير مصرح.
  4. **Web Scraping**: سرقة المحتوى.
- **التنفيذ**:  
  ```
  X-RateLimit-Limit: 100
  X-RateLimit-Remaining: 99
  X-RateLimit-Reset: 1625097600
  ```

---

### **10. لماذا Logging ضروري؟**
- **لأجل**:
  1. **التصحيح**: معرفة سبب الأخطاء.
  2. **المراقبة**: اكتشاف الأنشطة المشبوهة.
  3. **التدقيق**: تتبع من فعل ماذا ومتى.
  4. **الامتثال**: متطلبات قانونية (GDPR، PCI-DSS).
- **مثال ضروري**: سجل محاولات الدخول الفاشلة.

---

## 🧪 أسئلة (ماذا لو؟)

### **1. ماذا لو قبلت أي URL؟**
- **الثغرة**: SSRF مباشرة.
- **الهجوم**: طلب موارد داخلية.
- **الحل**: Whitelist للdomains المسموحة فقط.

### **2. ماذا لو سمحت بالتحويل؟**
- **الثغرة**: Open Redirect.
- **الهجوم**: Phishing.
- **الحل**: التحقق من أن الوجهة داخل نفس النطاق.

### **3. ماذا لو لم تتحقق من الملكية؟**
- **الثغرة**: BOLA (Broken Object Level Authorization).
- **الهجوم**: الوصول لبيانات الآخرين.
- **الحل**: التحقق في كل طلب API.

### **4. ماذا لو أعدت كل الحقول؟**
- **الثغرة**: Information Disclosure.
- **الهجوم**: كشف بيانات حساسة.
- **الحل**: إرجاع الحقول الضرورية فقط.

### **5. ماذا لو لم تراقب؟**
- **المشكلة**: لا تعرف عن الهجمات.
- **النتيجة**: اختراق ناجح دون اكتشاف.
- **الحل**: سجلات مع تحليل تلقائي.

---

## ✍️ تمرين تطبيقي (مختبر الجزء العاشر)

### **1. خدمة جلب URL (مع ثغرة SSRF)**

#### **الكود الضعيف:**
```php
// fetch.php - خدمة جلب محتوى URL
class URLFetcher {
    public function fetchContent($url) {
        // 1. لا تحقق من الـ URL - ثغرة SSRF!
        $content = file_get_contents($url);
        
        // 2. إرجاع المحتوى مباشرة
        return $content;
    }
    
    public function displayPage() {
        $url = $_GET['url'] ?? '';
        if ($url) {
            $content = $this->fetchContent($url);
            echo "<h3>محتوى $url:</h3>";
            echo "<pre>" . htmlspecialchars($content) . "</pre>";
        }
        
        echo '
        <form method="GET">
            URL: <input type="text" name="url" value="https://example.com">
            <button type="submit">جلب</button>
        </form>
        ';
    }
}

// الاستخدام: fetch.php?url=http://localhost/admin
```

#### **هجوم SSRF:**
```http
# 1. قراءة ملفات النظام
GET /fetch.php?url=file:///etc/passwd

# 2. الوصول للـ metadata في السحابة (AWS)
GET /fetch.php?url=http://169.254.169.254/latest/meta-data/

# 3. مسح الشبكة الداخلية
GET /fetch.php?url=http://192.168.1.1/admin
GET /fetch.php?url=http://localhost:8080/management

# 4. استخدام بروتوكولات أخرى
GET /fetch.php?url=gopher://internal-server:3306/_SELECT%20*%20FROM%20users

# 5. DNS Rebinding Attack
# المهاجم يتحكم بـ DNS يعطي:
# - أولاً: IP خارجي (للتحقق)
# - ثانياً: 127.0.0.1 (للتنفيذ)
GET /fetch.php?url=http://attacker-controlled-domain.com/
```

#### **الإصلاح بالـ Whitelist:**
```php
class SecureURLFetcher {
    private $allowedDomains = [
        'example.com',
        'api.example.com',
        'cdn.example.com'
    ];
    
    private $allowedSchemes = ['http', 'https'];
    
    public function fetchContent($url) {
        // 1. التحقق من الـ URL
        $parsed = parse_url($url);
        
        if (!$parsed || !isset($parsed['host'])) {
            throw new InvalidURLException('URL غير صالح');
        }
        
        // 2. التحقق من البروتوكول
        if (!in_array($parsed['scheme'] ?? '', $this->allowedSchemes)) {
            throw new InvalidURLException('البروتوكول غير مسموح');
        }
        
        // 3. التحقق من النطاق (Domain)
        $host = $parsed['host'];
        $allowed = false;
        
        foreach ($this->allowedDomains as $domain) {
            if ($host === $domain || str_ends_with($host, '.' . $domain)) {
                $allowed = true;
                break;
            }
        }
        
        if (!$allowed) {
            throw new InvalidURLException('النطاق غير مسموح');
        }
        
        // 4. منع عناوين IP الخاصة
        if ($this->isPrivateIP($host)) {
            throw new InvalidURLException('لا يمكن الوصول لعناوين داخلية');
        }
        
        // 5. تعطيل اتباع الـ Redirects تلقائياً
        $context = stream_context_create([
            'http' => [
                'follow_location' => 0, // لا تتبع redirects
                'timeout' => 5, // timeout قصير
                'max_redirects' => 0
            ],
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true
            ]
        ]);
        
        // 6. استخدام cURL مع تحكم أفضل
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false, // لا تتبع redirects
            CURLOPT_MAXREDIRS => 0,
            CURLOPT_TIMEOUT => 5,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_RESOLVE => [], // لمنع DNS Rebinding
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
            CURLOPT_IPRESOLVE => CURL_IPRESOLVE_V4 // إجبار IPv4
        ]);
        
        $content = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);
        
        if ($error) {
            throw new FetchException("خطأ في جلب المحتوى: $error");
        }
        
        // 7. التحقق من نوع المحتوى
        $contentType = curl_getinfo($ch, CURLINFO_CONTENT_TYPE) ?? '';
        if (strpos($contentType, 'text/') === false && 
            strpos($contentType, 'application/json') === false) {
            throw new InvalidContentException('نوع المحتوى غير مسموح');
        }
        
        return [
            'content' => $content,
            'http_code' => $httpCode,
            'content_type' => $contentType
        ];
    }
    
    private function isPrivateIP($host) {
        // تحقق إذا كان عنوان IP
        if (!filter_var($host, FILTER_VALIDATE_IP)) {
            return false;
        }
        
        // قائمة بعناوين IP الخاصة
        $privateRanges = [
            '10.0.0.0/8',
            '172.16.0.0/12',
            '192.168.0.0/16',
            '127.0.0.0/8',
            '169.254.0.0/16', // Link-local
            '::1/128', // IPv6 localhost
            'fc00::/7', // IPv6 private
            'fe80::/10' // IPv6 link-local
        ];
        
        foreach ($privateRanges as $range) {
            if ($this->ipInRange($host, $range)) {
                return true;
            }
        }
        
        return false;
    }
    
    private function ipInRange($ip, $range) {
        if (strpos($range, '/') === false) {
            return $ip === $range;
        }
        
        list($subnet, $bits) = explode('/', $range);
        $ip = inet_pton($ip);
        $subnet = inet_pton($subnet);
        
        if ($ip === false || $subnet === false) {
            return false;
        }
        
        // للحصول على القناع
        $bytes = strlen($ip);
        $mask = str_repeat(chr(255), $bits / 8);
        if ($bits % 8 != 0) {
            $mask .= chr(bindec(str_pad(str_repeat('1', $bits % 8), 8, '0')));
        }
        $mask = str_pad($mask, $bytes, chr(0));
        
        return ($ip & $mask) === $subnet;
    }
}
```

### **2. Open Redirect واستغلاله**

#### **الكود الضعيف:**
```php
// redirect.php - نظام التحويل
class RedirectHandler {
    public function redirectUser($target) {
        // ثغرة: أي URL مقبول
        header("Location: $target");
        exit;
    }
    
    public function loginRedirect() {
        $redirectTo = $_GET['redirect'] ?? '/dashboard';
        // لا تحقق!
        $this->redirectUser($redirectTo);
    }
}

// الاستخدام: login.php?redirect=https://evil.com/phishing
```

#### **هجوم Open Redirect:**
```http
# 1. هجوم Phishing مباشر
GET /login.php?redirect=https://evil-phishing.com

# 2. إخفاء الرابط الحقيقي
GET /login.php?redirect=https%3A%2F%2Fevil.com%2Flogin%3Fsite%3Dreal-bank.com

# 3. استخدام JavaScript في الرابط (نادر)
GET /login.php?redirect=javascript:alert(document.cookie)

# 4. تحويل داخل تحويل
GET /login.php?redirect=/logout?redirect=https://evil.com
```

#### **الإصلاح:**
```php
class SecureRedirectHandler {
    private $allowedDomains = [
        'example.com',
        'app.example.com'
    ];
    
    public function safeRedirect($target) {
        // 1. التحقق من أن الـ URL صالح
        if (!filter_var($target, FILTER_VALIDATE_URL)) {
            // 2. إذا كان مساراً نسبياً، تحويل داخلي
            if (strpos($target, '/') === 0) {
                $this->localRedirect($target);
                return;
            }
            throw new InvalidRedirectException('رابط تحويل غير صالح');
        }
        
        $parsed = parse_url($target);
        
        // 3. منع JavaScript URLs
        if (isset($parsed['scheme']) && $parsed['scheme'] === 'javascript') {
            throw new InvalidRedirectException('رابط JavaScript غير مسموح');
        }
        
        // 4. منع data URLs
        if (isset($parsed['scheme']) && $parsed['scheme'] === 'data') {
            throw new InvalidRedirectException('رابط data غير مسموح');
        }
        
        // 5. التحقق من النطاق
        if (isset($parsed['host'])) {
            $allowed = false;
            foreach ($this->allowedDomains as $domain) {
                if ($parsed['host'] === $domain || 
                    str_ends_with($parsed['host'], '.' . $domain)) {
                    $allowed = true;
                    break;
                }
            }
            
            if (!$allowed) {
                throw new InvalidRedirectException('التحويل خارج النطاق غير مسموح');
            }
        }
        
        // 6. تحقق إضافي لمنع Open Redirect
        $this->additionalChecks($target);
        
        // 7. تسجيل عملية التحويل
        $this->logRedirect($target);
        
        // 8. استخدام header مع encoding آمن
        header('Location: ' . $target, true, 302);
        exit;
    }
    
    public function loginRedirect() {
        $redirectTo = $_GET['redirect'] ?? '';
        
        // إذا لم يكن هناك تحويل، الرجوع للوحة التحكم
        if (empty($redirectTo)) {
            $this->localRedirect('/dashboard');
            return;
        }
        
        // التحقق من أن الهدف مسار داخلي نسبي فقط
        if (strpos($redirectTo, '/') === 0) {
            // مسار نسبي - مسموح
            $this->safeRedirect($redirectTo);
        } else {
            // محاولة تحويل خارجي - رفض
            $this->localRedirect('/dashboard');
        }
    }
    
    private function localRedirect($path) {
        // إضافة النطاق الأساسي
        $baseUrl = $_SERVER['REQUEST_SCHEME'] . '://' . $_SERVER['HTTP_HOST'];
        $fullUrl = $baseUrl . $path;
        
        header('Location: ' . $fullUrl, true, 302);
        exit;
    }
    
    private function additionalChecks($url) {
        // قائمة بأنماط خطيرة
        $dangerousPatterns = [
            '//evil.com',
            '@evil.com',
            'javascript:',
            'data:',
            'vbscript:',
            'file://',
            'gopher://',
            'telnet://'
        ];
        
        foreach ($dangerousPatterns as $pattern) {
            if (stripos($url, $pattern) !== false) {
                throw new InvalidRedirectException('رابط يحتوي على نمط خطير');
            }
        }
        
        // التحقق من الترميز المزدوج
        $decoded = urldecode($url);
        if ($decoded !== $url) {
            // إذا كان هناك ترميز، تحقق من النسخة المفكوكة أيضاً
            foreach ($dangerousPatterns as $pattern) {
                if (stripos($decoded, $pattern) !== false) {
                    throw new InvalidRedirectException('رابط مخلل');
                }
            }
        }
    }
    
    private function logRedirect($target) {
        $log = sprintf(
            "[%s] Redirect: %s -> %s | IP: %s | User-Agent: %s",
            date('Y-m-d H:i:s'),
            $_SERVER['REQUEST_URI'],
            $target,
            $_SERVER['REMOTE_ADDR'],
            $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'
        );
        
        file_put_contents('/var/log/redirects.log', $log . PHP_EOL, FILE_APPEND);
    }
}
```

### **3. استغلال BOLA (Broken Object Level Authorization)**

#### **الكود الضعيف:**
```php
// api.php - REST API مع ثغرة BOLA
class UserAPI {
    // GET /api/users/{id}
    public function getUser($id) {
        // لا تحقق من الملكية!
        $user = $this->findUser($id);
        
        // إرجاع جميع البيانات
        return [
            'id' => $user['id'],
            'email' => $user['email'],
            'phone' => $user['phone'], // حساس!
            'address' => $user['address'], // حساس!
            'payment_methods' => $user['payment_methods'] // خطير!
        ];
    }
    
    // PUT /api/users/{id}
    public function updateUser($id, $data) {
        // Mass Assignment خطر!
        $this->db->table('users')
                ->where('id', $id)
                ->update($data); // يحدث جميع الحقول!
                
        return ['success' => true];
    }
}

// الهجوم: GET /api/users/123 (أنا المستخدم 456)
// يرى بيانات المستخدم 123!
```

#### **استغلال BOLA:**
```http
# 1. قراءة بيانات مستخدم آخر
GET /api/users/1001
Authorization: Bearer [token للمستخدم 1000]

# 2. تعديل بيانات مستخدم آخر
PUT /api/users/1001
Authorization: Bearer [token للمستخدم 1000]
Content-Type: application/json

{
    "email": "hacker@evil.com",
    "role": "admin",
    "balance": 1000000
}

# 3. حذف مستخدم آخر
DELETE /api/users/1001
Authorization: Bearer [token للمستخدم 1000]

# 4. الوصول لموارد مرتبطة
GET /api/users/1001/orders
GET /api/users/1001/messages
GET /api/users/1001/payment-cards
```

#### **تطبيق تحقق الملكية:**
```php
class SecureUserAPI {
    private $currentUserId;
    
    public function __construct($token) {
        $this->currentUserId = $this->validateToken($token);
    }
    
    // GET /api/users/{id}
    public function getUser($id) {
        // 1. التحقق من الملكية
        if (!$this->isOwner($id)) {
            throw new AccessDeniedException('غير مصرح بالوصول لهذا المورد');
        }
        
        $user = $this->findUser($id);
        
        // 2. إرجاع البيانات الضرورية فقط
        return $this->sanitizeUserData($user);
    }
    
    // PUT /api/users/{id}
    public function updateUser($id, $data) {
        // 1. التحقق من الملكية
        if (!$this->isOwner($id)) {
            throw new AccessDeniedException('غير مصرح بتعديل هذا المستخدم');
        }
        
        // 2. تصفية الحقول المسموح بها فقط
        $allowedFields = ['name', 'avatar', 'preferences'];
        $filteredData = $this->filterFields($data, $allowedFields);
        
        // 3. التحقق من صحة القيم
        $this->validateUserData($filteredData);
        
        // 4. التحديث
        $this->db->table('users')
                ->where('id', $id)
                ->update($filteredData);
                
        return [
            'success' => true,
            'updated_fields' => array_keys($filteredData)
        ];
    }
    
    // نظام أكثر أماناً: User-Can-User
    public function userCan($action, $resource, $resourceId) {
        $policies = [
            'view' => function($userId, $resourceId) {
                // يمكن للمستخدم رؤية نفسه فقط
                return $userId == $resourceId;
            },
            'edit' => function($userId, $resourceId) {
                // يمكن للمستخدم تعديل نفسه فقط
                return $userId == $resourceId;
            },
            'delete' => function($userId, $resourceId) {
                // لا يمكن للمستخدم حذف نفسه (يحتاج مدير)
                return false;
            },
            'view_orders' => function($userId, $resourceId) {
                // يمكن رؤية الطلبات الخاصة به فقط
                return $userId == $resourceId;
            }
        ];
        
        if (!isset($policies[$action])) {
            return false;
        }
        
        return $policies[$action]($this->currentUserId, $resourceId);
    }
    
    // Middleware للتحقق من الملكية
    public function ownershipMiddleware($request, $response, $next) {
        $resourceId = $request->getAttribute('resource_id');
        $action = $request->getAttribute('action');
        
        if (!$this->userCan($action, 'user', $resourceId)) {
            // تسجيل محاولة الوصول غير المصرح
            $this->logUnauthorizedAccess($resourceId, $action);
            
            return $response->withJson([
                'error' => 'access_denied',
                'message' => 'غير مصرح بالوصول لهذا المورد'
            ], 403);
        }
        
        return $next($request, $response);
    }
    
    private function isOwner($resourceId) {
        return $this->currentUserId == $resourceId;
    }
    
    private function sanitizeUserData($user) {
        // إرجاع البيانات العامة فقط
        $publicData = [
            'id' => $user['id'],
            'name' => $user['name'],
            'avatar' => $user['avatar'],
            'join_date' => $user['created_at']
        ];
        
        // إذا كان المستخدم يرى بياناته الخاصة
        if ($this->currentUserId == $user['id']) {
            $privateData = [
                'email' => $user['email'],
                'phone' => substr($user['phone'], -4), // آخر 4 أرقام فقط
                'preferences' => $user['preferences']
            ];
            return array_merge($publicData, $privateData);
        }
        
        return $publicData;
    }
    
    private function filterFields($data, $allowedFields) {
        return array_filter($data, function($key) use ($allowedFields) {
            return in_array($key, $allowedFields);
        }, ARRAY_FILTER_USE_KEY);
    }
    
    private function logUnauthorizedAccess($resourceId, $action) {
        $log = sprintf(
            "[%s] UNAUTHORIZED: User %s tried to %s resource %s | IP: %s",
            date('Y-m-d H:i:s'),
            $this->currentUserId,
            $action,
            $resourceId,
            $_SERVER['REMOTE_ADDR']
        );
        
        file_put_contents('/var/log/access_violations.log', $log . PHP_EOL, FILE_APPEND);
        
        // تنبيه إذا كانت هناك محاولات متكررة
        $this->checkForAttacks();
    }
}
```

### **4. تطبيق Rate Limiting**

#### **نظام Rate Limiting متكامل:**
```php
class RateLimiter {
    private $storage;
    private $limits;
    
    public function __construct() {
        $this->storage = new RedisStorage();
        
        // تحديد الحدود لكل نوع من الطلبات
        $this->limits = [
            'login' => [
                'limit' => 5,  // 5 محاولات
                'window' => 300, // في 5 دقائق
                'block' => 900  // حظر 15 دقيقة إذا تجاوز
            ],
            'api_general' => [
                'limit' => 100, // 100 طلب
                'window' => 60   // في دقيقة
            ],
            'api_sensitive' => [
                'limit' => 10,  // 10 طلبات
                'window' => 300  // في 5 دقائق
            ],
            'password_reset' => [
                'limit' => 3,   // 3 طلبات
                'window' => 3600 // في ساعة
            ]
        ];
    }
    
    public function check($key, $type = 'api_general') {
        if (!isset($this->limits[$type])) {
            return true;
        }
        
        $limit = $this->limits[$type];
        $current = $this->getCurrentCount($key, $type);
        
        if ($current >= $limit['limit']) {
            // إذا تم حظر هذا النوع مؤقتاً
            if (isset($limit['block'])) {
                $blocked = $this->storage->get("blocked:$key:$type");
                if ($blocked) {
                    throw new RateLimitExceededException(
                        'تم حظرك مؤقتاً. حاول مرة أخرى لاحقاً.',
                        429,
                        ['retry_after' => $blocked]
                    );
                }
                
                // حظر مؤقت
                $this->storage->set(
                    "blocked:$key:$type",
                    time() + $limit['block'],
                    $limit['block']
                );
            }
            
            throw new RateLimitExceededException(
                'تجاوزت الحد المسموح للطلبات.',
                429,
                [
                    'limit' => $limit['limit'],
                    'remaining' => 0,
                    'reset' => $this->getResetTime($key, $type)
                ]
            );
        }
        
        // زيادة العداد
        $this->increment($key, $type);
        
        return [
            'limit' => $limit['limit'],
            'remaining' => $limit['limit'] - $current - 1,
            'reset' => $this->getResetTime($key, $type)
        ];
    }
    
    public function middleware($request, $response, $next) {
        // تحديد نوع الطلب
        $path = $request->getUri()->getPath();
        $method = $request->getMethod();
        
        $type = $this->determineLimitType($path, $method);
        
        // إنشاء مفتاح Rate limiting
        $key = $this->createKey($request);
        
        try {
            $limits = $this->check($key, $type);
            
            // إضافة الرؤوس للاستجابة
            $response = $response->withHeader('X-RateLimit-Limit', $limits['limit'])
                                 ->withHeader('X-RateLimit-Remaining', $limits['remaining'])
                                 ->withHeader('X-RateLimit-Reset', $limits['reset']);
            
            return $next($request, $response);
            
        } catch (RateLimitExceededException $e) {
            // إضافة رأس Retry-After
            $data = $e->getData();
            if (isset($data['retry_after'])) {
                $response = $response->withHeader('Retry-After', $data['retry_after']);
            }
            
            return $response->withJson([
                'error' => 'rate_limit_exceeded',
                'message' => $e->getMessage(),
                'retry_after' => $data['retry_after'] ?? null
            ], 429);
        }
    }
    
    private function determineLimitType($path, $method) {
        // تحديد نوع الطلب بناءً على المسار والطريقة
        if (strpos($path, '/login') !== false) {
            return 'login';
        }
        
        if (strpos($path, '/password-reset') !== false) {
            return 'password_reset';
        }
        
        if (strpos($path, '/api/') !== false) {
            // طلبات API الحساسة
            $sensitivePaths = ['/pay', '/transfer', '/delete', '/admin'];
            foreach ($sensitivePaths as $sensitive) {
                if (strpos($path, $sensitive) !== false) {
                    return 'api_sensitive';
                }
            }
            return 'api_general';
        }
        
        return 'api_general';
    }
    
    private function createKey($request) {
        // استخدام IP + User Agent + User ID (إذا موجود)
        $ip = $request->getServerParams()['REMOTE_ADDR'] ?? 'unknown';
        $userAgent = $request->getHeaderLine('User-Agent') ?? 'unknown';
        $userId = $this->getUserIdFromRequest($request) ?? 'anonymous';
        
        // لمنع المهاجمين من تغيير الـ User Agent بسهولة
        $userAgentHash = substr(md5($userAgent), 0, 8);
        
        return "ratelimit:$ip:$userAgentHash:$userId";
    }
    
    private function getCurrentCount($key, $type) {
        $windowKey = "{$key}:{$type}:" . floor(time() / $this->limits[$type]['window']);
        return $this->storage->get($windowKey) ?? 0;
    }
    
    private function increment($key, $type) {
        $windowKey = "{$key}:{$type}:" . floor(time() / $this->limits[$type]['window']);
        $this->storage->increment($windowKey, $this->limits[$type]['window']);
    }
    
    private function getResetTime($key, $type) {
        $currentWindow = floor(time() / $this->limits[$type]['window']);
        return ($currentWindow + 1) * $this->limits[$type]['window'];
    }
    
    private function getUserIdFromRequest($request) {
        // محاولة الحصول على User ID من التوكن
        $authHeader = $request->getHeaderLine('Authorization');
        if (strpos($authHeader, 'Bearer ') === 0) {
            $token = substr($authHeader, 7);
            return $this->extractUserIdFromToken($token);
        }
        
        return null;
    }
}

class RedisStorage {
    private $redis;
    
    public function __construct() {
        $this->redis = new Redis();
        $this->redis->connect('127.0.0.1', 6379);
    }
    
    public function get($key) {
        return $this->redis->get($key);
    }
    
    public function set($key, $value, $ttl) {
        return $this->redis->setex($key, $ttl, $value);
    }
    
    public function increment($key, $ttl) {
        $pipeline = $this->redis->pipeline();
        $pipeline->incr($key);
        $pipeline->expire($key, $ttl);
        $pipeline->exec();
        
        return $this->redis->get($key);
    }
}
```

### **5. نظام تسجيل الأحداث الشامل**

```php
class SecurityLogger {
    private $logFile;
    private $syslogEnabled;
    
    public function __construct($config) {
        $this->logFile = $config['log_file'] ?? '/var/log/application.log';
        $this->syslogEnabled = $config['syslog_enabled'] ?? false;
    }
    
    public function log($level, $message, $context = []) {
        $logEntry = $this->formatLogEntry($level, $message, $context);
        
        // التسجيل في ملف
        file_put_contents($this->logFile, $logEntry, FILE_APPEND);
        
        // التسجيل في Syslog (اختياري)
        if ($this->syslogEnabled) {
            syslog($this->getSyslogPriority($level), $message);
        }
        
        // تنبيهات للأحداث الخطيرة
        if ($level === 'CRITICAL' || $level === 'ALERT') {
            $this->sendAlert($level, $message, $context);
        }
    }
    
    public function logSecurityEvent($eventType, $details) {
        $context = array_merge($details, [
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'timestamp' => microtime(true),
            'request_id' => $this->generateRequestId()
        ]);
        
        $this->log('SECURITY', $eventType, $context);
        
        // تحليل الأحداث الأمنية
        $this->analyzeSecurityEvent($eventType, $context);
    }
    
    private function formatLogEntry($level, $message, $context) {
        $entry = sprintf(
            "[%s] [%s] %s",
            date('Y-m-d H:i:s'),
            $level,
            $message
        );
        
        if (!empty($context)) {
            $entry .= " | " . json_encode($context, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        }
        
        return $entry . PHP_EOL;
    }
    
    private function analyzeSecurityEvent($eventType, $context) {
        // تحليل الأحداث للكشف عن الهجمات
        $analysisRules = [
            'FAILED_LOGIN' => function($context) {
                // إذا كانت هناك أكثر من 5 محاولات فاشلة من نفس IP
                $count = $this->countEvents('FAILED_LOGIN', $context['ip'], 300);
                if ($count > 5) {
                    $this->log('ALERT', 'Possible brute force attack', $context);
                }
            },
            'UNAUTHORIZED_ACCESS' => function($context) {
                // محاولات وصول غير مصرح
                $count = $this->countEvents('UNAUTHORIZED_ACCESS', $context['ip'], 600);
                if ($count > 3) {
                    $this->log('ALERT', 'Multiple unauthorized access attempts', $context);
                }
            },
            'RATE_LIMIT_EXCEEDED' => function($context) {
                // تجاوز معدل الطلبات
                if ($context['count'] > 100) {
                    $this->log('CRITICAL', 'Possible DoS attack', $context);
                }
            }
        ];
        
        if (isset($analysisRules[$eventType])) {
            $analysisRules[$eventType]($context);
        }
    }
    
    private function countEvents($eventType, $ip, $timeWindow) {
        // عد الأحداث في نافذة زمنية معينة
        // (يجب تنفيذ تخزين مناسب في production)
        $key = "event_count:{$eventType}:{$ip}:" . floor(time() / $timeWindow);
        $count = apcu_fetch($key) ?: 0;
        apcu_store($key, $count + 1, $timeWindow);
        
        return $count;
    }
    
    private function sendAlert($level, $message, $context) {
        // إرسال تنبيه عبر البريد أو Slack أو SMS
        $alert = [
            'level' => $level,
            'message' => $message,
            'context' => $context,
            'time' => date('Y-m-d H:i:s')
        ];
        
        // تخزين التنبيه
        $this->storeAlert($alert);
        
        // إرساله (اختياري)
        if ($level === 'CRITICAL') {
            $this->sendCriticalAlert($alert);
        }
    }
    
    private function generateRequestId() {
        return bin2hex(random_bytes(8));
    }
}

// استخدام النظام
$logger = new SecurityLogger([
    'log_file' => '/var/log/app-security.log',
    'syslog_enabled' => true
]);

// تسجيل أحداث مختلفة
$logger->logSecurityEvent('LOGIN_SUCCESS', [
    'user_id' => 123,
    'method' => 'password'
]);

$logger->logSecurityEvent('FAILED_LOGIN', [
    'username' => 'admin',
    'reason' => 'wrong_password'
]);

$logger->logSecurityEvent('UNAUTHORIZED_ACCESS', [
    'resource' => '/api/users/456',
    'attempted_by' => 123
]);
```

---

## ✅ الخلاصة

1. **SSRF أخطر مما تتخيل**: يمكنه اختراق الشبكة الداخلية.
2. **Open Redirect بوابة للـ Phishing**: تحقق من جميع الـ URLs.
3. **BOLA ثغرة شائعة**: تحقق من الملكية في كل طلب API.
4. **Rate Limiting ضروري**: لمنع Abuse والهجمات.
5. **التسجيل الشامل**: بدون سجلات، أنت أعمى.

