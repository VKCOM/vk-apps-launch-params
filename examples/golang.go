package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type queryParameter struct {
	Key   string
	Value string
}

type LaunchParams struct {
	// Идентификатор пользователя.
	UserId int
	// Идентификатор приложения.
	AppId int
}

// Ошибки, возвращаемые VerifyLaunchParams.
const (
	SignInvalid = "подпись невалидна"
	Expired     = "срок действия подписи истёк"
)

func main() {
	const (
		clientUrl    = "https://example.com/?vk_user_id=494075&vk_app_id=6736218&vk_is_app_user=1&vk_are_notifications_enabled=1&vk_language=ru&vk_access_token_settings=&vk_platform=android&sign=htQFduJpLxz7ribXRZpDFUH-XEUhC9rBPTJkjUFEkRA"
		clientSecret = "wvl68m4dR1UpLrVRli"
	)

	// Обратите внимание на то, что в этом примере expiresIn равен 0. При
	// разработке рекомендуется передавать значение отличное от 0. Почему
	// передавать 0 не стоит описано в пояснении к параметру expiresIn функции
	// VerifyLaunchParams.
	if _, err := VerifyLaunchParams(clientUrl, clientSecret, 0); err == nil {
		fmt.Println("ok")
	} else {
		fmt.Println("fail")
	}
}

// VerifyLaunchParams проверяет, были ли переданные параметры запуска
// сгенерированы указанным секретным ключом. Также, функция проверяет, истёк ли
// срок действия этих параметров запуска.
//
// querySearch - параметры запуска в виде строки полученный от клиентского
// приложения в формате search (window.location.search) либо
// полного url (window.location.toString()).
//
// secretKey - секретный ключ мини-приложения.
//
// expiresIn - срок жизни параметров запуска с момента их выдачи. В случае
// передачи значения 0, срок действия жизни параметров не проверяется.
// Использование значения 0 крайне не рекомендуется ввиду того, что в случае
// кражи параметров запуска пользователя, у злоумышленника всегда будут
// действующие данные, которые позволяет ему представляться другим
// пользователем.
func VerifyLaunchParams(
	querySearch string,
	secretKey string,
	expiresIn int,
) (*LaunchParams, error) {
	var searchIndex = strings.Index(querySearch, "?")

	// Необходимо удалить всё, что находится до search части в случае, если
	// эта часть существует.
	if searchIndex >= 0 {
		querySearch = querySearch[searchIndex+1:]
	}

	var (
		// Идентификатор приложения.
		appId int
		// Отфильтрованные параметры запуска. Мы используем именно
		// слайс по той причине, что позже нам будет необходимым этот слайс
		// отсортировать по возрастанию ключа параметра.
		query []queryParameter
		// Подпись, которая была сгенерирована сервером ВКонтакте и основана на
		// параметрах из query.
		sign string
		// Дата, когда параметры запуска были созданы.
		timestamp int
		// Идентификатор пользователя.
		userId int
	)

	// Разделяем параметры запуска на вхождения, разделенные знаком "&".
	for _, part := range strings.Split(querySearch, "&") {
		var keyAndValue = strings.Split(part, "=")
		var key = keyAndValue[0]
		var value = keyAndValue[1]

		// Мы обрабатываем только те ключи, которые начинаются с префикса "vk_".
		// Все остальные ключи в создании подписи не участвуют.
		if strings.HasPrefix(key, "vk_") {
			switch key {
			case "vk_ts": // дата выдачи параметров запуска.
			case "vk_app_id": // идентификатор приложения.
			case "vk_user_id": // идентификатор пользователя.
				if intValue, err := strconv.Atoi(value); err == nil {
					if key == "vk_ts" {
						timestamp = intValue
					} else if key == "vk_app_id" {
						appId = intValue
					} else if key == "vk_user_id" {
						userId = intValue
					}
				}
			}
			query = append(query, queryParameter{key, value})
		} else if key == "sign" {
			// Если ключ равен "sign", то в значении записана подпись параметров
			// запуска.
			sign = value
		}
	}

	// В случае, если подпись параметров не удалось найти, либо параметров с
	// префиксом "vk_" передано не было, мы считаем параметры запуска невалидными.
	if sign == "" || len(query) == 0 {
		return nil, errors.New(SignInvalid)
	}

	// В случае, если требуется проверка на истечения срока годности параметров
	// запуска, мы требуем наличие параметра "vk_ts" и проверяем его.
	if expiresIn > 0 && (timestamp == 0 || time.Now().After(time.Unix(int64(timestamp+expiresIn), 0))) {
		return nil, errors.New(Expired)
	}

	// Сортируем параметры запуска по порядку их возрастания.
	sort.SliceStable(query, func(a int, b int) bool {
		return query[a].Key < query[b].Key
	})

	// Далее снова превращаем параметры запуска в единую строку.
	var queryString = ""

	for idx, param := range query {
		if idx > 0 {
			queryString += "&"
		}
		queryString += param.Key + "=" + url.PathEscape(param.Value)
	}

	// Далее нам необходимо вычислить хэш SHA-256.
	var hashCreator = hmac.New(sha256.New, []byte(secretKey))
	hashCreator.Write([]byte(queryString))

	var hash = base64.URLEncoding.EncodeToString(hashCreator.Sum(nil))

	// Далее по правилам создания параметров запуска ВКонтакте, необходимо
	// произвести ряд замен символов.
	hash = strings.Replace(hash, "+", "-", -1)
	hash = strings.Replace(hash, "/", "_", -1)
	hash = strings.Replace(hash, "=", "", -1)

	if sign != hash {
		return nil, errors.New(SignInvalid)
	}
	return &LaunchParams{
		UserId: userId,
		AppId:  appId,
	}, nil
}
