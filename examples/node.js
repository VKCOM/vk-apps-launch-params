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

console.log(areLaunchParamsValid ? 'ok' : 'fail');