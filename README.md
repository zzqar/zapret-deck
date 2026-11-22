# Zapret Deck

Плагин [Decky Loader](https://decky.xyz) для Steam Deck. Обходит блокировки Steam, Roblox и Telegram во Вьетнаме без VPN. Включается одним тумблером в меню `...`.

- **Обход DPI**: `nfqws` мешает провайдеру прочитать имя сайта.
- **Защищённый DNS**: DNS-over-TLS к 1.1.1.1 / 8.8.8.8, чтобы провайдер не подменял адреса на 127.0.0.1.

## Установка

1. **Desktop Mode.** `Steam` → **Питание** → **Переключиться на рабочий стол**.
2. **Пароль.** В Konsole выполни `passwd`, если пароль ещё не задан.
3. **Decky Loader.** Скачай `decky_installer.desktop` с <https://decky.xyz>, запусти его и выбери **Release**.
4. **Режим разработчика.** В игровом режиме: `...` → Decky → ⚙️ → включи **Developer mode**.
5. **Плагин.** `...` → Decky → ⚙️ → **Developer** → **Install Plugin from URL**, вставь ссылку:
   ```
   https://zzqar.github.io/zapret-deck/z.zip
   ```
6. **Запуск.** `...` → **Zapret Deck** → **«Скачать nfqws»** → включи **«Защищённый DNS»** и **«Включить»**.
7. **Проверка.** **«Проверить Steam»**: всё должно быть ✅. Перезапусти Steam.

Обновление: повтори шаг 5. Подробности и решение проблем: [INSTALL.md](INSTALL.md).

## Безопасность

- Плагин ничего не отправляет о тебе. В сеть он ходит только к GitHub (скачать nfqws), к 1.1.1.1 / 8.8.8.8 (DNS) и к сайтам из «Проверить Steam».
- `nfqws` закреплён на версии v72.13. SHA-256 архива и бинарника сверяется при установке и перед каждым запуском. Бинарник лежит в папке, доступной на запись только root.
- При выключении правила файрвола и DNS возвращаются как были.

## Если не работает

- **`DNS подменён → 127.x`**: проверь, что «Защищённый DNS» включён, переподключи Wi-Fi.
- **❌ при нормальном IP**: выбери другую стратегию `VN · …`.
- **Не открывается конкретный сайт**: допиши домен в `~/zapret-deck/lists/vietnam.txt` или обнови страницу 2–3 раза, и он попадёт в автосписок.
- **Сайт стал работать хуже**: добавь домен в `~/zapret-deck/lists/exclude.txt`.

## Настройка

Файлы в `~/zapret-deck/`, редактируются без sudo. После правки нажми «Перезапустить nfqws».

| Путь | Что это |
|---|---|
| `strategies/*.conf` | стратегии |
| `lists/vietnam.txt` | Steam, Roblox, Telegram |
| `lists/steam.txt`, `lists/discord.txt` | дополнительные списки |
| `lists/exclude.txt` | домены, которые не трогаются |
| `lists/autohostlist.txt` | домены, найденные автоматически |

Пример стратегии:

```
# name: Моя стратегия
# tcp: 80,443
# udp: 443
--filter-tcp=80,443 {hostlist} {exclude} {autohostlist}
--dpi-desync=multidisorder --dpi-desync-split-pos=1,midsld
```

Плейсхолдеры: `{hostlist}`, `{exclude}`, `{autohostlist}`, `{fake_tls}`, `{fake_quic}`.

## Разработка

```bash
pnpm install && pnpm build
python3 tests/smoke.py
./deploy.sh deck@steamdeck.local
```

Релиз: `git tag vX.Y.Z && git push --tags`.

## Связь

Telegram: [@zzqar](https://t.me/zzqar)

## Лицензия

MIT
