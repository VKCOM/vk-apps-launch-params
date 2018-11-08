# vk-apps-launch-params
Пример работы с параметрами запуска

## Пример проверки подписи на PHP
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

## Пример проверки подписи на Kotlin
```kotlin
/**
* Function return userid and verify user data
*
* @param launchAppQueryParams query which send from VK where app open
* @param authProfile secret data about app (like app secret)
*/
private fun onAppOpenWithQuery(launchAppQueryParams: String, authProfile: AuthProfile): Int {
    // Create string for hashing
    val decodeStr = URLDecoder.decode(launchAppQueryParams)
    val params = decodeStr.split("&").map { it.split("=").toPair() }
    val checkString = params.asSequence().filter { it.first.startsWith("vk_") }
            .map { it.second }
            .joinTo(StringBuilder(), ",", authProfile.appSecret).toString()
            
    // Hashing 
    val md = MessageDigest.getInstance("SHA-256")
    val digest = md.digest(checkString.toByteArray())
    val hash = Base64.getEncoder().encodeToString(digest)
            .replace('+', '-').replace('/', '_')
            .trim('=')
            
    // Using data
    val paramsMap = params.toMap()
    if (paramsMap.containsKey("vk_user_id") && paramsMap["sign"].equals(hash)) {
        return paramsMap["vk_user_id"]!!.toInt()
    }
    return 0
}
```
