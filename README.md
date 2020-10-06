# vk-apps-launch-params
Информация о параметрах запуска на платформе VK Mini Apps.

## Оглавление
- [Основная информация](#intro)
    - [Как параметры запуска попадают в приложение](#how-params-are-passed)
    - [Аутентификация пользователей на сервере](#auth)
- [Пример передачи параметров запуска на сервер](#how-to-send-launch-params)
    - [Cons](#cons)
    - [Pros](#pros)
- [Примеры проверки подписи на различных языка](#examples)
    - [PHP](#php)  
    - [Java (1.8)](#java1p8)  
    - [Python 3](#python3)  
    - [Node](#node)
    - [TypeScript](#typescript)
  
<a name="intro"/>
  
## Основная информация
Параметрами запуска называются те параметры, которые передаются от ВКонтакте
приложению VK Mini Apps. Они могут содержать информацию разного характера -
место, где приложение запущено (каталог приложений, сообщество, обычное
открытие по ссылке и другие), идентификаторы приложения и пользователя, включены
ли у пользователя уведомления, какая локализация выбрана пользователя и многие
другие. С полным списком параметров запуска можно ознакомиться в [официальной
документации](https://vk.com/dev/vk_apps_docs3?f=6.%2B%D0%9F%D0%B0%D1%80%D0%B0%D0%BC%D0%B5%D1%82%D1%80%D1%8B%2B%D0%B7%D0%B0%D0%BF%D1%83%D1%81%D0%BA%D0%B0).

<a name="how-params-are-passed"/>

### Как параметры запуска попадают в приложение

Каждый раз, когда приложение VK Mini Apps запускается, ВКонтакте, в качестве
источника приложения берет указанный в настройках URL (или URL для 
разработки, если вы являетесь администратором приложения), и в конец добавляет
строку поиска, куда и помещает параметры запуска в виде query-параметров. Таким
образом, URL, который будет доступен изнутри вашего приложения будет иметь
вид:

`https://example.com/?vk_app_id=111&vk_user_id=222&sign=mvkasjdl22Ds&...`

> **Примечание:**
>
> Стоит помнить, что все параметры запуска VK Mini Apps начинаются с префикса 
> `vk_`. Так же, имеется дополнительный параметр, именуемый `sign`. Основная его
> задача - быть гарантом того, что все переданные параметры запуска являются 
> валидными, то есть не подделаны. Как его использовать, будет рассмотрено 
> далее.

<a name="auth"/>

### Аутентификация пользователей на сервере

Параметры запуска имеют достаточно важную и полезную особенность - их можно
использовать в качестве аутентификационных данных на разработанном вами 
backend-сервисе. Это позволяет сократить время разработки и не утруждать себя
написанием своей собственной системой аутентификации.

Как уже и было упомянуто ранее, вместе с параметрами запуска передается такой
параметр как `sign`, который является подписью всех параметров, что гарантирует
серверу их корректность и правдивость.

Безопасность подписи обеспечивается вашим секретным ключом приложения. При 
создании подписи используется алгоритм хэширования SHA-256, где в качестве
ключа указывается ваш секретный ключ. Таким образом, не зная секретного ключа,
злоумышленник не способен подделать параметры запуска.

<a name="how-to-send-launch-params"/>

## Передача параметров запуска на сервер

Для того, чтобы получить список параметров запуска в строковом виде, достаточно
обратиться к `window.location.search`:

```javascript
// Используем slice(1) для того, чтобы отбросить знак вопроса в начале.
const params = window.location.search.slice(1);
```

Далее, если нам необходимо конвертировать их из строкового вида в объект,
воспользуемся встроенной в node библиотекой `querystring`:

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

Разработчики, зачастую, допускают ошибку, используя explicit-метод (неявный, 
интуитивно непонятный) передачи - используют прикрепляемый браузером заголовок 
Referer, который равен текущему адресу страницы. 

Дело в том, что при любых запросах стоит запрещать браузеру прикреплять этот
заголовок. Его использование чревато тем, что при запросе на какой-либо 
сторонний сервер, вы, сами того не зная, передадите ему свои параметры запуска.
Этим самым, вы отдадите свои аутентификационные данные, после чего злоумышленник
сможет представиться вашему серверу другим пользователем. Как решить эту 
проблему, читайте [здесь](https://stackoverflow.com/a/32014225).

<a name="pros"/>

### Pros

Самым простым и корректным решением является явная передача своего заголовка и
проверка его на серверной стороне.

```javascript
import axios from 'axios';

// Создаем инстанс axios.
const http = axios.create({
  headers: {
    // Прикрепляем заголовок, отвечающий за параметры запуска.
    'x-launch-params': window.location.search.slice(1),
  }
});

// Теперь, при попытке сделать запросы при помощи ранее созданного инстанса
// axios (именуемого "http"), он будет автоматически прикреплять необходимый 
// нам заголовок, который мы сможем проверить на серверной стороне.
```

После того, как заголовок успешно прикрепляется, необходимо добавить его 
проверку на серверной стороне.

<a name="examples"/>

## Примеры проверки подписи на различных языка

<a name="php"/>

### PHP

```php
$url = 'https://example.com/?vk_user_id=494075&vk_app_id=6736218&vk_is_app_user=1&vk_are_notifications_enabled=1&vk_language=ru&vk_access_token_settings=&vk_platform=android&sign=exTIBPYTrAKDTHLLm2AwJkmcVcvFCzQUNyoa6wAjvW6k';
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
        String url = "https://example.com/?vk_user_id=494075&vk_app_id=6736218&vk_is_app_user=1&vk_are_notifications_enabled=1&vk_language=ru&vk_access_token_settings=&vk_platform=android&sign=exTIBPYTrAKDTHLLm2AwJkmcVcvFCzQUNyoa6wAjvW6k";
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
from collections import OrderedDict
from hashlib import sha256
from hmac import HMAC
from urllib.parse import urlparse, parse_qsl, urlencode


def is_valid(*, query: dict, secret: str) -> bool:
    """Check VK Apps signature"""
    vk_subset = OrderedDict(sorted(x for x in query.items() if x[0][:3] == "vk_"))
    hash_code = b64encode(HMAC(secret.encode(), urlencode(vk_subset, doseq=True).encode(), sha256).digest())
    decoded_hash_code = hash_code.decode('utf-8')[:-1].replace('+', '-').replace('/', '_')
    return query["sign"] == decoded_hash_code


url = "https://example.com/?vk_user_id=494075&vk_app_id=6736218&vk_is_app_user=1&vk_are_notifications_enabled=1&vk_language=ru&vk_access_token_settings=&vk_platform=android&sign=exTIBPYTrAKDTHLLm2AwJkmcVcvFCzQUNyoa6wAjvW6k"
client_secret = "wvl68m4dR1UpLrVRli"  # Защищённый ключ из настроек вашего приложения

# Если без Flask или Django
query_params = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
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
   * корректного в контексте подписи параметра, добавляет его в массив
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
    // Если строка начинается с вопроса (если передан window.location.search),
    // его необходимо удалить.
    const formattedSearch = searchOrParsedUrlQuery.startsWith('?')
      ? searchOrParsedUrlQuery.slice(1)
      : searchOrParsedUrlQuery;

    // Пытаемся спарсить строку, как query-параметр.
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
  // Обрабатываем исключительный случай, когда подпись в параметрах не найдена,
  // а также не найден ни один параметр, начинающийся с "vk_", дабы избежать
  // излишней нагрузки образующейся в процессе работы дальнейшего кода.
  if (!sign || queryParams.length === 0) {
    return false;
  }
  // Снова создаем query в виде строки из уже отфильтрованных параметров.
  const queryString = queryParams
    // Сортируем ключи в порядке возрастания.
    .sort((a, b) => a.key.localeCompare(b.key))
    // Воссоздаем новый query в виде строки.
    .reduce((acc, {key, value}, idx) => {
      return acc + (idx === 0 ? '' : '&') + `${key}=${value}`;
    }, '');

  // Создаем хэш получившейся строки на основе секретного ключа.
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

const url = 'https://example.com/?vk_user_id=494075&vk_app_id=6736218&vk_is_app_user=1&vk_are_notifications_enabled=1&vk_language=ru&vk_access_token_settings=&vk_platform=android&sign=exTIBPYTrAKDTHLLm2AwJkmcVcvFCzQUNyoa6wAjvW6k';
const clientSecret = 'wvl68m4dR1UpLrVRli'; // Защищённый ключ из настроек вашего приложения

// Берем только параметры запуска.
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
   * корректного в контексте подписи параметра, добавляет его в массив
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
    // Если строка начинается с вопроса (если передан window.location.search),
    // его необходимо удалить.
    const formattedSearch = searchOrParsedUrlQuery.startsWith('?')
      ? searchOrParsedUrlQuery.slice(1)
      : searchOrParsedUrlQuery;

    // Пытаемся спарсить строку, как query-параметр.
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
  // Обрабатываем исключительный случай, когда подпись в параметрах не найдена,
  // а также не найден ни один параметр, начинающийся с "vk_", дабы избежать
  // излишней нагрузки образующейся в процессе работы дальнейшего кода.
  if (!sign || queryParams.length === 0) {
    return false;
  }
  // Снова создаем query в виде строки из уже отфильтрованных параметров.
  const queryString = queryParams
    // Сортируем ключи в порядке возрастания.
    .sort((a, b) => a.key.localeCompare(b.key))
    // Воссоздаем новый query в виде строки.
    .reduce<string>((acc, {key, value}, idx) => {
      return acc + (idx === 0 ? '' : '&') + `${key}=${value}`;
    }, '');

  // Создаем хэш получившейся строки на основе секретного ключа.
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

const url = 'https://example.com/?vk_user_id=494075&vk_app_id=6736218&vk_is_app_user=1&vk_are_notifications_enabled=1&vk_language=ru&vk_access_token_settings=&vk_platform=android&sign=exTIBPYTrAKDTHLLm2AwJkmcVcvFCzQUNyoa6wAjvW6k';
const clientSecret = 'wvl68m4dR1UpLrVRli'; // Защищённый ключ из настроек вашего приложения

// Берем только параметры запуска.
const launchParams = url.slice(url.indexOf('?') + 1);

// Проверяем, валидны ли параметры запуска.
const areLaunchParamsValid = verifyLaunchParams(launchParams, clientSecret);
```