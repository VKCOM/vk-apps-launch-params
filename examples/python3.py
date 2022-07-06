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