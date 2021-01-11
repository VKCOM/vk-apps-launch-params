# vk-apps-launch-params
Информация о параметрах запуска на платформе VK Mini Apps.

## Оглавление
- [Основная информация](#intro)
    - [Как параметры запуска попадают в приложение](#how-params-are-passed)
    - [Аутентификация пользователей на сервере](#auth)
- [Передача параметров запуска на сервер](#how-to-send-launch-params)
    - [Cons](#cons)
    - [Pros](#pros)
- [Примеры проверки подписи на различных языках](#examples)
    - [PHP](#php)  
    - [Java (1.8)](#java1p8)  
    - [Python 3](#python3)  
    - [Node](#node)
    - [TypeScript](#typescript)
  
<a name="intro"/>
  
## Основная информация
Приложение VK Mini Apps получает от ВКонтакте параметры запуска. Они могут содержать различную информацию: место запуска (каталог приложений, сообщество, обычное открытие по ссылке и т.д.), идентификаторы пользователя и приложения, включены ли у пользователя уведомления, какой выбран язык и многие другие. С полным списком параметров запуска можно ознакомиться в [официальной
документации](https://vk.com/dev/vk_apps_docs3?f=6.%2B%D0%9F%D0%B0%D1%80%D0%B0%D0%BC%D0%B5%D1%82%D1%80%D1%8B%2B%D0%B7%D0%B0%D0%BF%D1%83%D1%81%D0%BA%D0%B0).

<a name="how-params-are-passed"/>

### Как параметры запуска попадают в приложение

Каждый раз, когда мини-приложение запускается, ВКонтакте берёт указанный в настройках URL (или URL для разработки, если вы являетесь администратором приложения) и добавляет в конец строку поиска вместе с query-параметрами запуска. Таким образом, URL, доступный изнутри вашего приложения, будет иметь примерно такой вид:

`https://example.com/?vk_app_id=111&vk_user_id=222&sign=mvkasjdl22Ds&...`

> **Примечание:**
>
> Стоит помнить, что параметры запуска мини-приложения начинаются с префикса `vk_`. Но есть и дополнительный параметр — `sign`. Он отвечает за то, что все переданные параметры запуска являются валидными, то есть не подделаны. Как использовать `sign` рассмотрим ниже.

<a name="auth"/>

### Аутентификация пользователей на сервере

Параметры запуска имеют важную и полезную особенность — их можно использовать как аутентификационные данные на разработанном вами backend-сервисе. Это позволяет сократить время разработки и не утруждать себя написанием собственной системы аутентификации.

Вместе с параметрами запуска, как мы уже писали, передаётся `sign` — подпись, гарантирующая серверу корректность и правдивость параметров.

Безопасность подписи обеспечивается алгоритмом хеширования SHA-256, использующим секретный ключ вашего мини-приложения. Таким образом, не зная ключа, злоумышленник не сможет подделать параметры запуска.

<a name="how-to-send-launch-params"/>

## Передача параметров запуска на сервер

Для того чтобы получить список параметров запуска в строковом виде, достаточно
обратиться к `window.location.search`:

```javascript
// Используем slice(1), для того чтобы отбросить начальный знак вопроса.
const params = window.location.search.slice(1);
```

Если необходимо конвертировать параметры из строкового вида в объект, воспользуемся встроенной в node библиотекой `querystring`:

```javascript
import qs from 'querystring';
// или
const qs = require('querystring');

const params = window.location.search.slice(1);
const paramsAsObject = qs.parse(params);

// Теперь мы можем использовать эти параметры как нам заблагорассудится.
```

<a name="cons"/>

### Cons

Разработчики зачастую допускают ошибку, используя неявный и интуитивно непонятный explicit-метод передачи, — прикрепляемый браузером заголовок Referer, совпадающий с текущим адресом страницы.

Стоит запрещать браузеру прикреплять этот заголовок, иначе при запросе на какой-либо сторонний сервер вы можете, сами того не подозревая, передать ему свои параметры запуска. После этого злоумышленник получит возможность представиться вашему серверу другим пользователем, используя его аутентификационные данные. Как решить эту проблему, читайте [здесь](https://stackoverflow.com/a/32014225).

<a name="pros"/>

### Pros

Самым простым и корректным решением является явная передача своего заголовка и
проверка его на серверной стороне.

```javascript
import axios from 'axios';

// Создаём инстанс axios.
const http = axios.create({
  headers: {
    // Прикрепляем заголовок, отвечающий за параметры запуска.
    Authorization: `Bearer ${window.location.search.slice(1)}`,
  }
});

// Теперь при попытке сделать запросы при помощи ранее созданного инстанса
// axios (именуемого "http"), он будет автоматически прикреплять необходимый 
// нам заголовок, который мы сможем проверить на серверной стороне.
```

После того, как заголовок успешно прикрепляется, необходимо добавить его 
проверку на серверной стороне.

<a name="examples"/>

## Примеры проверки подписи на различных языках

<a name="php"/>

### PHP

```php
$url = 'https://example.com/?vk_user_id=494075&vk_app_id=6736218&vk_is_app_user=1&vk_are_notifications_enabled=1&vk_language=ru&vk_access_token_settings=&vk_platform=android&sign=htQFduJpLxz7ribXRZpDFUH-XEUhC9rBPTJkjUFEkRA';
$client_secret = 'wvl68m4dR1UpLrVRli'; //Защищённый ключ из настроек вашего приложения

$query_params = [];
parse_str(parse_url($url, PHP_URL_QUERY), $query_params); // Получаем query-параметры из URL

$sign_params = [];
foreach ($query_params as $name => $value) {
  if (strpos($name, 'vk_') !== 0) { // Получаем только vk параметры из query
    continue;
  }

  $sign_params[$name] = $value;
}

ksort($sign_params); // Сортируем массив по ключам 
$sign_params_query = http_build_query($sign_params); // Формируем строку вида "param_name1=value&param_name2=value"
$sign = rtrim(strtr(base64_encode(hash_hmac('sha256', $sign_params_query, $client_secret, true)), '+/', '-_'), '='); // Получаем хеш-код от строки, используя защищеный ключ приложения. Генерация на основе метода HMAC. 

$status = $sign === $query_params['sign']; // Сравниваем полученную подпись со значением параметра 'sign'

echo ($status ? 'ok' : 'fail')."\n";
```

<a name="java1p8"/>

### Java (1.8)

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

class Application {

    private static final String ENCODING = "UTF-8";

    public static void main(String[] args) throws java.lang.Exception {
        String url = "https://example.com/?vk_user_id=494075&vk_app_id=6736218&vk_is_app_user=1&vk_are_notifications_enabled=1&vk_language=ru&vk_access_token_settings=&vk_platform=android&sign=htQFduJpLxz7ribXRZpDFUH-XEUhC9rBPTJkjUFEkRA";
        String clientSecret = "wvl68m4dR1UpLrVRli";

        Map<String, String> queryParams = getQueryParams(new URL(url));

        String checkString = queryParams.entrySet().stream()
                .filter(entry -> entry.getKey().startsWith("vk_"))
                .sorted(Map.Entry.comparingByKey())
                .map(entry -> encode(entry.getKey()) + "=" + encode(entry.getValue()))
                .collect(Collectors.joining("&"));

        String sign = getHashCode(checkString, clientSecret);
        System.out.println(sign.equals(queryParams.getOrDefault("sign", "")) ? "ok" : "fail");
    }


    private static Map<String, String> getQueryParams(URL url) {
        final Map<String, String> result = new LinkedHashMap<>();
        final String[] pairs = url.getQuery().split("&");

        for (String pair : pairs) {
            int idx = pair.indexOf("=");
            String key = idx > 0 ? decode(pair.substring(0, idx)) : pair;
            String value = idx > 0 && pair.length() > idx + 1 ? decode(pair.substring(idx + 1)) : null;
            result.put(key, value);
        }

        return result;
    }

    private static String getHashCode(String data, String key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(ENCODING), "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(secretKey);
        byte[] hmacData = mac.doFinal(data.getBytes(ENCODING));
        return new String(Base64.getUrlEncoder().withoutPadding().encode(hmacData));
    }


    private static String decode(String value) {
        try {
            return URLDecoder.decode(value, ENCODING);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        return value;
    }

    private static String encode(String value) {
        try {
            return URLEncoder.encode(value, ENCODING);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        return value;
    }
}
```

<a name="python3"/>

### Python 3

```python
from base64 import b64encode
from hashlib import sha256
from hmac import HMAC
from urllib.parse import urlparse, parse_qsl, urlencode 

def is_valid(query: dict, secret: str) -> bool:
    """

    Check VK Apps signature

    :param dict query: Словарь с параметрами запуска
    :param str secret: Секретный ключ приложения ("Защищённый ключ")
    :returns: Результат проверки подписи
    :rtype: bool

    """
    if not query.get("sign"):
        return False
    
    vk_subset = sorted(
        filter(
            lambda key: key.startswith("vk_"), 
            query
        )
    )

    if not vk_subset:
        return False

    ordered = {k: query[k] for k in vk_subset}

    hash_code = b64encode(
        HMAC(
            secret.encode(), 
            urlencode(ordered, doseq=True).encode(), 
            sha256
        ).digest()
    ).decode("utf-8")

    if hash_code[-1] == "=":
        hash_code = hash_code[:-1]

    fixed_hash = hash_code.replace('+', '-').replace('/', '_')
    return query.get("sign") == fixed_hash



# Пример использования

url = "https://example.com/?vk_user_id=494075&vk_app_id=6736218&vk_is_app_user=1&vk_are_notifications_enabled=1&vk_language=ru&vk_access_token_settings=&vk_platform=android&sign=htQFduJpLxz7ribXRZpDFUH-XEUhC9rBPTJkjUFEkRA"
client_secret = "wvl68m4dR1UpLrVRli" # Защищённый ключ из настроек вашего приложения


query_params = dict(
    parse_qsl(
        urlparse(url).query, 
        keep_blank_values=True
    )
)
status = is_valid(query=query_params, secret=client_secret)

print("ok" if status else "fail")
```

<a name="node"/>

### Node JS

```javascript
const crypto = require('crypto');

/**
 * Верифицирует параметры запуска.
 * @param searchOrParsedUrlQuery
 * @param {string} secretKey
 * @returns {boolean}
 */
function verifyLaunchParams(searchOrParsedUrlQuery, secretKey) {
  let sign;
  const queryParams = [];

  /**
   * Функция, которая обрабатывает входящий query-параметр. В случае передачи
   * параметра, отвечающего за подпись, подменяет "sign". В случае встречи
   * корректного в контексте подписи параметра добавляет его в массив
   * известных параметров.
   * @param key
   * @param value
   */
  const processQueryParam = (key, value) => {
    if (typeof value === 'string') {
      if (key === 'sign') {
        sign = value;
      } else if (key.startsWith('vk_')) {
        queryParams.push({key, value});
      }
    }
  };

  if (typeof searchOrParsedUrlQuery === 'string') {
    // Если строка начинается с вопроса (когда передан window.location.search),
    // его необходимо удалить.
    const formattedSearch = searchOrParsedUrlQuery.startsWith('?')
      ? searchOrParsedUrlQuery.slice(1)
      : searchOrParsedUrlQuery;

    // Пытаемся спарсить строку как query-параметр.
    for (const param of formattedSearch.split('&')) {
      const [key, value] = param.split('=');
      processQueryParam(key, value);
    }
  } else {
    for (const key of Object.keys(searchOrParsedUrlQuery)) {
      const value = searchOrParsedUrlQuery[key];
      processQueryParam(key, value);
    }
  }
  // Обрабатываем исключительный случай, когда не найдена ни подпись в параметрах,
  // ни один параметр, начинающийся с "vk_", дабы избежать
  // излишней нагрузки, образующейся в процессе работы дальнейшего кода.
  if (!sign || queryParams.length === 0) {
    return false;
  }
  // Снова создаём query в виде строки из уже отфильтрованных параметров.
  const queryString = queryParams
    // Сортируем ключи в порядке возрастания.
    .sort((a, b) => a.key.localeCompare(b.key))
    // Воссоздаём новый query в виде строки.
    .reduce((acc, {key, value}, idx) => {
      return acc + (idx === 0 ? '' : '&') + `${key}=${encodeURIComponent(value)}`;
    }, '');

  // Создаём хеш получившейся строки на основе секретного ключа.
  const paramsHash = crypto
    .createHmac('sha256', secretKey)
    .update(queryString)
    .digest()
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=$/, '');

  return paramsHash === sign;
}

const url = 'https://example.com/?vk_user_id=494075&vk_app_id=6736218&vk_is_app_user=1&vk_are_notifications_enabled=1&vk_language=ru&vk_access_token_settings=&vk_platform=android&sign=htQFduJpLxz7ribXRZpDFUH-XEUhC9rBPTJkjUFEkRA';
const clientSecret = 'wvl68m4dR1UpLrVRli'; // Защищённый ключ из настроек вашего приложения

// Берём только параметры запуска.
const launchParams = url.slice(url.indexOf('?') + 1);

// Проверяем, валидны ли параметры запуска.
const areLaunchParamsValid = verifyLaunchParams(launchParams, clientSecret);
```

<a name="typescript"/>

### TypeScript

```typescript
import {ParsedUrlQuery} from 'querystring';
import crypto from 'crypto';

interface IQueryParam {
  key: string;
  value: string;
}

/**
 * Верифицирует параметры запуска.
 * @param searchOrParsedUrlQuery
 * @param {string} secretKey
 * @returns {boolean}
 */
function verifyLaunchParams(
  searchOrParsedUrlQuery: string | ParsedUrlQuery,
  secretKey: string,
): boolean {
  let sign: string | undefined;
  const queryParams: IQueryParam[] = [];

  /**
   * Функция, которая обрабатывает входящий query-параметр. В случае передачи
   * параметра, отвечающего за подпись, подменяет "sign". В случае встречи
   * корректного в контексте подписи параметра добавляет его в массив
   * известных параметров.
   * @param key
   * @param value
   */
  const processQueryParam = (key: string, value: any) => {
    if (typeof value === 'string') {
      if (key === 'sign') {
        sign = value;
      } else if (key.startsWith('vk_')) {
        queryParams.push({key, value});
      }
    }
  };

  if (typeof searchOrParsedUrlQuery === 'string') {
    // Если строка начинается с вопроса (когда передан window.location.search),
    // его необходимо удалить.
    const formattedSearch = searchOrParsedUrlQuery.startsWith('?')
      ? searchOrParsedUrlQuery.slice(1)
      : searchOrParsedUrlQuery;

    // Пытаемся спарсить строку как query-параметр.
    for (const param of formattedSearch.split('&')) {
      const [key, value] = param.split('=');
      processQueryParam(key, value);
    }
  } else {
    for (const key of Object.keys(searchOrParsedUrlQuery)) {
      const value = searchOrParsedUrlQuery[key];
      processQueryParam(key, value);
    }
  }
  // Обрабатываем исключительный случай, когда не найдена ни подпись в параметрах,
  // ни один параметр, начинающийся с "vk_", дабы избежать
  // излишней нагрузки, образующейся в процессе работы дальнейшего кода.
  if (!sign || queryParams.length === 0) {
    return false;
  }
  // Снова создаём query в виде строки из уже отфильтрованных параметров.
  const queryString = queryParams
    // Сортируем ключи в порядке возрастания.
    .sort((a, b) => a.key.localeCompare(b.key))
    // Воссоздаем новый query в виде строки.
    .reduce<string>((acc, {key, value}, idx) => {
      return acc + (idx === 0 ? '' : '&') + `${key}=${encodeURIComponent(value)}`;
    }, '');

  // Создаём хеш получившейся строки на основе секретного ключа.
  const paramsHash = crypto
    .createHmac('sha256', secretKey)
    .update(queryString)
    .digest()
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=$/, '');

  return paramsHash === sign;
}

const url = 'https://example.com/?vk_user_id=494075&vk_app_id=6736218&vk_is_app_user=1&vk_are_notifications_enabled=1&vk_language=ru&vk_access_token_settings=&vk_platform=android&sign=htQFduJpLxz7ribXRZpDFUH-XEUhC9rBPTJkjUFEkRA';
const clientSecret = 'wvl68m4dR1UpLrVRli'; // Защищённый ключ из настроек вашего приложения

// Берём только параметры запуска.
const launchParams = url.slice(url.indexOf('?') + 1);

// Проверяем, валидны ли параметры запуска.
const areLaunchParamsValid = verifyLaunchParams(launchParams, clientSecret);
```

