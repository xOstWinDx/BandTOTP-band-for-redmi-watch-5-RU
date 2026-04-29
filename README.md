# BandTOTP RU

Русифицированная версия приложения BandTOTP для часов Xiaomi/HyperOS/Vela.

Связанный Android-клиент:
[BandTOTP-android-for-redmi-watch-5-RU](https://github.com/xOstWinDx/BandTOTP-android-for-redmi-watch-5-RU)

Приложение генерирует TOTP-коды прямо на часах, хранит ключи в прежнем storage-ключе `keys` и принимает данные через прежний `system.interconnect`, чтобы не ломать связку с Android-клиентом.

## Что изменено

- Переведен интерфейс часов, сообщения, экран "О приложении" и документация.
- Жесткая верстка `192x490` заменена на адаптивную: приложение получает размер экрана через `system.device` и пересчитывает высоту интерфейса под браслеты, прямоугольные и круглые часы.
- Убран тяжелый 10-мс таймер прогресса. Обновление идет раз в секунду, а HMAC пересчитывается только при смене временного окна.
- Секрет Base32 декодируется один раз при загрузке аккаунта, а не при каждом обновлении кода.
- Добавлен импорт JSON-экспортов Google Authenticator и строк `otpauth://`.
- Удалены неиспользуемые PNG-экраны с китайским текстом, чтобы уменьшить будущий `rpk`.

## Поддерживаемые форматы импорта

Старый формат остается рабочим:

```json
{
  "list": [
    { "name": "GitHub", "usr": "user@example.com", "key": "BASE32SECRET" }
  ]
}
```

Также поддерживаются строки `otpauth://`:

```text
otpauth://totp/GitHub:user@example.com?secret=BASE32SECRET&issuer=GitHub&digits=6&period=30
```

И JSON-массивы объектов:

```json
[
  {
    "issuer": "GitHub",
    "name": "user@example.com",
    "secret": "BASE32SECRET",
    "algorithm": "SHA1",
    "digits": 6,
    "period": 30,
    "type": "totp"
  }
]
```

Импорт Google Authenticator после декодирования migration-экспорта тоже поддержан, если объект содержит `otp_params` или `otpParams`.

## Ограничения

- Приложение рассчитано на TOTP. HOTP-записи из экспорта пропускаются, потому что для них нужен счетчик, а не время.
- Steam-коды работают через отдельный формат генерации. Если аккаунт называется Steam или тип содержит `steam`, будет использован Steam TOTP.
- Ключ хранения на часах не менялся: `keys`.

## Сборка RPK

Нужен Node.js 18 или новее.

Установка зависимостей:

```sh
npm install
```

Debug-сборка:

```sh
npm run build
```

Release-сборка:

```sh
npm run release
```

Готовый файл появляется в `dist/`, например:

```text
dist/com.lst.bandtotp.release.1.2.rpk
```

Особенность этого форка: исходники лежат в корне, а `aiot-toolkit` 2.0 ожидает папку `src/`. Скрипты сборки автоматически создают временную `src/` из нужных файлов проекта перед запуском `aiot`.

Для release-сборки нужны `private.pem` и `certificate.pem` в `sign/release/` или сразу в `sign/`. Для локальной тестовой сборки можно взять временный сертификат из toolkit:

```sh
mkdir -p sign/release
cp node_modules/@aiot-toolkit/aiotpack/lib/compiler/javascript/vela/utils/signature/pem/private.pem sign/release/private.pem
cp node_modules/@aiot-toolkit/aiotpack/lib/compiler/javascript/vela/utils/signature/pem/certificate.pem sign/release/certificate.pem
```

Для публикации и нормального распространения лучше создать собственную подпись в AIoT-IDE и хранить приватный ключ вне git.

## Полезные ссылки

- Android-клиент этого форка: https://github.com/xOstWinDx/BandTOTP-android-for-redmi-watch-5-RU
- Часовой репозиторий этого форка: https://github.com/xOstWinDx/BandTOTP-band-for-redmi-watch-5-RU
- Android-клиент: https://github.com/leset0ng/BandTOTP-Android
- AstroBox-клиент: https://github.com/leset0ng/BandTotp-astrobox
- Страница оригинального проекта: https://www.bandbbs.cn/resources/2119/
- Документация AIoT-toolkit: https://iot.mi.com/vela/quickapp/en/tools/toolkit/start.html
- Упаковка приложения: https://iot.mi.com/vela/quickapp/zh/tools/release/start.html
