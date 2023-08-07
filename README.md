# PHP helper functions

### Note: These functions are modified according to my needs. I'll add more details to it

## Validates single input of an HTML form or regular data

```
function validateInput($data)
{
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data);
    return $data;
}
```

## Validates all input of an HTML form or any 1D array

It uses `validateInput` for each fields

```
function validateFormData($arr)
{
    if (!is_array($arr)) return false;
    foreach ($arr  as $key => $val) {
        $arr[$key] = validateInput($val);
    }
    return $arr;
}
```

## Get RAW json input from HTTP in PHP Array format

```
function getRawInput()
{
    $handler = fopen('php://input', 'r');
    return json_decode(stream_get_contents($handler), true);
}
```

## Format date as required

```
function formatDate($date = '', $formate = 'M d, Y')
{
    $date = $date == '' ? date('Y-m-d') : $date;
    return date($formate, strtotime($date));
}
```

## Set session value for a key

```
function setSession($var, $value = '')
{
    $_SESSION[$var] = $value;
    return true;
}
```

## Get session value for a key

```
function getSession($var)
{
    return $_SESSION[$var] ?? null;
}
```

## Unset a session value for a key

```
function unsetSession($var)
{
    unset($_SESSION[$var]);
}
```

## Reset whole session

```
function resetSession()
{
    unset($_SESSION);
}
```

## Remove unwanted fields from 1D array

```
function removeExceptKeys($arr, $keepKeys = [])
{
    foreach ($arr as $key => $value) {
        if (!in_array($key, $keepKeys))
            unset($arr[$key]);
    }
    return $arr;
}
```

## Keep only required fields and remove others from 1D array

```
function removeKeys($arr, $keysToRemove = [])
{
    foreach ($keysToRemove as $i) {
        $pos = array_search($i, $arr);
        unset($arr[$pos]);
    }
    return $arr;
}
```

## Amount to word in Bangla, Indian format

```function amountToWord($amount)
{
    $amountParts = explode('.', $amount);
    $rupees = (int) $amountParts[0];
    $paisa = isset($amountParts[1]) ? (int) $amountParts[1] : 0;

    $fmt = new NumberFormatter('en-IN', NumberFormatter::SPELLOUT);
    $result = $fmt->format($rupees) . ' Taka';

    if ($paisa > 0) {
        $paisa_words = $fmt->format($paisa) . ' Paisa';
        $result .= ' and ' . $paisa_words;
    }
    return ucwords($result);
}```

## Generate random string of length N

```
function generateRandomString($length = 6)
{
    $allowedChars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    $allowedCharsLen = strlen($allowedChars);
    $randString = '';
    for ($i = 0; $i < $length; $i++) {
        $randString .= $allowedChars[rand(0, $allowedCharsLen - 1)];
    }
    return $randString;
}
```

## Get language header from HTTP

Note: I got this from a post which I don't recall

```
function getLanguageHeader()
{
    $headers = null;
    if (isset($_SERVER['HTTP_ACCEPT_LANGUAGE'])) {
        $headers = trim($_SERVER["HTTP_ACCEPT_LANGUAGE"]);
    } else if (isset($_SERVER['HTTP_HTTP_ACCEPT_LANGUAGE'])) { //Nginx or fast CGI
        $headers = trim($_SERVER["HTTP_HTTP_ACCEPT_LANGUAGE"]);
    } elseif (function_exists('apache_request_headers')) {
        $requestHeaders = apache_request_headers();
        // Server-side fix for bug in old Android versions (a nice side-effect of this fix means we don't care about capitalization for HTTP_ACCEPT_LANGUAGE)
        $requestHeaders = array_combine(array_map('ucwords', array_keys($requestHeaders)), array_values($requestHeaders));
        if (isset($requestHeaders['HTTP_ACCEPT_LANGUAGE'])) {
            $headers = trim($requestHeaders['HTTP_ACCEPT_LANGUAGE']);
        }
    }
    if ($headers != 'en' && $headers != 'bn') $headers = 'en';
    return $headers;
}
```

## Upload base64 file to path

```
function uploadBase64($base64String, $path)
{
    if ($base64String == '' || $base64String == null) return '';
    $semicoloneSeparated = explode(';', $base64String);
    if (count($semicoloneSeparated) != 2) return '';
    list($type, $dataWithComma) = $semicoloneSeparated;

    list(, $base64)      = explode(',', $dataWithComma);
    $base64Decoded = base64_decode($base64);
    // check proper extension
    $types = explode('/', $type);

    if (count($types) != 2) return '';
    $ext = $types[1];
    $fileName = get_uuid() . '.' . $ext;
    return file_put_contents($path . $fileName, $base64Decoded) !== FALSE ? $fileName : '';
}
```

## Calculate age from today

```
function calculateAge($date)
{
    // Y-m-d format
    $bday = new DateTime($date); // Your date of birth
    $today = new Datetime(date('Y-m-d'));
    $age = $today->diff($bday);
    return $age->y;
}
```

## Convert English number into Bangla

```
function en2bn($number)
{
    $bn = array("১", "২", "৩", "৪", "৫", "৬", "৭", "৮", "৯", "০");
    $en = array("1", "2", "3", "4", "5", "6", "7", "8", "9", "0");
    return str_replace($en, $bn, $number);
}
```

## Convert Bangla number into English

```
function bn2en($number)
{
    $bn = array("১", "২", "৩", "৪", "৫", "৬", "৭", "৮", "৯", "০");
    $en = array("1", "2", "3", "4", "5", "6", "7", "8", "9", "0");
    return str_replace($bn, $en, $number);
}
```

## Encrypt data with key using Open SSL AES 256 CBC

Note: You can modify according to own methods

```
function encryptWithKey($data, $key)
{
    $encryption_key = base64_decode($key);
    $iv = generateRandomString();
    $encrypted = openssl_encrypt($data, 'aes-256-cbc', $encryption_key, 0, $iv);
    return base64_encode($encrypted . '::' . $iv);
}

```

## Decrypt data with key using Open SSL AES 256 CBC

Note: Use same methods that used in encryption `encryptWithKey`

```
function decryptWithKey($data, $key)
{
    $encryption_key = base64_decode($key);
    list($encrypted_data, $iv) = array_pad(explode('::', base64_decode($data), 2), 2, null);
    return openssl_decrypt($encrypted_data, 'aes-256-cbc', $encryption_key, 0, $iv);
}
```

## Set status header with code and custom text

Credit: Codeigniter 3

```
function setStatuseader($code = 200, $text = '')
{
    if (empty($text)) {
        is_int($code) or $code = (int) $code;
        $stati = array(
            100    => 'Continue',
            101    => 'Switching Protocols',

            200    => 'OK',
            201    => 'Created',
            202    => 'Accepted',
            203    => 'Non-Authoritative Information',
            204    => 'No Content',
            205    => 'Reset Content',
            206    => 'Partial Content',

            300    => 'Multiple Choices',
            301    => 'Moved Permanently',
            302    => 'Found',
            303    => 'See Other',
            304    => 'Not Modified',
            305    => 'Use Proxy',
            307    => 'Temporary Redirect',

            400    => 'Bad Request',
            401    => 'Unauthorized',
            402    => 'Payment Required',
            403    => 'Forbidden',
            404    => 'Not Found',
            405    => 'Method Not Allowed',
            406    => 'Not Acceptable',
            407    => 'Proxy Authentication Required',
            408    => 'Request Timeout',
            409    => 'Conflict',
            410    => 'Gone',
            411    => 'Length Required',
            412    => 'Precondition Failed',
            413    => 'Request Entity Too Large',
            414    => 'Request-URI Too Long',
            415    => 'Unsupported Media Type',
            416    => 'Requested Range Not Satisfiable',
            417    => 'Expectation Failed',
            422    => 'Unprocessable Entity',
            426    => 'Upgrade Required',
            428    => 'Precondition Required',
            429    => 'Too Many Requests',
            431    => 'Request Header Fields Too Large',

            500    => 'Internal Server Error',
            501    => 'Not Implemented',
            502    => 'Bad Gateway',
            503    => 'Service Unavailable',
            504    => 'Gateway Timeout',
            505    => 'HTTP Version Not Supported',
            511    => 'Network Authentication Required',
        );

        if (isset($stati[$code])) {
            $text = $stati[$code];
        } else {
            $code = 500;
            $text = 'No status text available.';
        }
    }

    if (strpos(PHP_SAPI, 'cgi') === 0) {
        header('Status: ' . $code . ' ' . $text, TRUE);
        return;
    }

    $server_protocol = (isset($_SERVER['SERVER_PROTOCOL']) && in_array($_SERVER['SERVER_PROTOCOL'], array('HTTP/1.0', 'HTTP/1.1', 'HTTP/2'), TRUE))
        ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.1';
    header($server_protocol . ' ' . $code . ' ' . $text, TRUE, $code);
}
```
