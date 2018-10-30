# vk-apps-launch-params
Пример работы с параметрами запуска

## Пример проверки подписи на PHP
```php
$url = 'https://example.com/?vk_user_id=494075&vk_app_id=6736218&vk_is_app_user=1&vk_are_notifications_enabled=1&vk_language=ru&vk_access_token_settings=&sign=exTIBPYTrAKDTHLLm2AwJkmcVcvFCzQUNyoa6wAjvW6k';
$client_secret = 'wvl68m4dR1UpLrVRli'; //Защищённый ключ из настроек вашего приложения

$params = [];
parse_str(parse_url($url, PHP_URL_QUERY), $params);

$sign_string = $client_secret;
foreach ($params as $name => $value) {
  if (strpos($name, 'vk_') !== 0) {
    continue;
  }

  $sign_string .= $value;
}


$sign = rtrim(strtr(base64_encode(hash('sha256', $sign_string, true)), '+/', '-_'), '=');
$status = $sign === $params['sign'];

echo ($status ? 'ok' : 'fail')."\n";
```
