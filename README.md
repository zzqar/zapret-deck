# Zapret Deck

Плагин для [Decky Loader](https://decky.xyz) на Steam Deck: обход блокировок Steam, Roblox и Telegram во Вьетнаме из меню Quick Access (`...`), без VPN. Скорость загрузок и пинг не меняются, трафик идёт напрямую.

**Как установить:** [INSTALL.md](INSTALL.md)

Провайдер блокирует двумя способами, плагин закрывает оба:

| Блокировка | Решение в плагине |
|---|---|
| DNS отдаёт 127.0.0.1 или глушит запросы | **Защищённый DNS**: локальный DNS-over-TLS резолвер на `127.0.0.77`, дальше к 1.1.1.1 / 8.8.8.8 |
| DPI читает SNI и рвёт HTTPS («ошибка 101») | **Обход DPI**: `nfqws` режет и переставляет пакеты, чтобы DPI не мог прочитать имя сайта |

## Как это работает

- Backend (`main.py`) работает от root.
- `nfqws --qnum=200` запускается с выбранной стратегией. nftables (таблица `inet zapret_deck`) отправляет в очередь первые исходящие пакеты на 80/443, а для автосписка ещё и первые входящие. Если nft нет, используется iptables.
- Защищённый DNS (`py_modules/dns_proxy.py`) переключает DNS активных Wi-Fi и Ethernet подключений через `nmcli device modify`. Профили сетей не меняются: если выключить DNS или выгрузить плагин, `nmcli device reapply` вернёт всё как было. Раз в 20 секунд плагин проверяет, не слетела ли настройка после смены сети.
- В правилах стоит `bypass`: если nfqws упадёт, трафик пойдёт напрямую и сеть не пропадёт.

## Стратегии

По умолчанию выбрана **Vietnam FPT (рабочая)**, подобранная под FPT Telecom: `multidisorder 1,midsld` для TCP, QUIC fake и автосписок с порогом 2. Стратегии `VN · …` — альтернативы для TCP, их стоит перебрать на Viettel и VNPT или если DPI обновился.

## Файлы

Всё лежит в `/home/deck/zapret-deck/` и редактируется без sudo. После правки нажмите «Перезапустить nfqws».

```
strategies/*.conf       стратегии
lists/vietnam.txt       Steam, Roblox, Telegram (тумблер в UI)
lists/steam.txt         расширенный список Steam (CDN, чат, трансляции)
lists/discord.txt       Discord
lists/exclude.txt       никогда не обходятся (банки, gov.vn)
lists/autohostlist.txt  найдено автоматически (после 2 неудач домен добавляется сам)
bin/nfqws, fake/        бинарник и fake-пакеты
```

## Формат стратегии

```
# name: Моя стратегия
# description: что делает
# tcp: 80,443
# udp: 443
--filter-tcp=80,443 {hostlist} {exclude} {autohostlist} --hostlist-auto-fail-threshold=2
--dpi-desync=multidisorder --dpi-desync-split-pos=1,midsld
--new
--filter-udp=443 {hostlist} {exclude} --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic={fake_quic}
```

Плейсхолдеры:
- `{hostlist}` — `--hostlist=` для каждого включённого списка.
- `{exclude}` — `exclude.txt`.
- `{autohostlist}` — автосписок. Если он есть в стратегии, включается перехват входящих пакетов.
- `{fake_tls}`, `{fake_quic}` — fake-файлы.

`# tcp:` и `# udp:` задают порты, которые перехватываются firewall'ом. Аргументы `--dpi-desync…` совпадают с Windows-версией nfqws, достаточно заменить пути на плейсхолдеры.

## Разработка

```bash
pnpm install
pnpm build                       # dist/index.js
./deploy.sh deck@steamdeck.local # сборка + установка на Deck по SSH
```

Релиз: `git tag v0.1.0 && git push --tags`. Workflow соберёт `zapret-deck.zip` и приложит его к GitHub Release.

## Лицензия

MIT, см. [LICENSE](LICENSE).
