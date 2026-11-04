# shadowrocket-rules

Списки правил для Shadowrocket, собранные из [runetfreedom/russia-v2ray-rules-dat](https://github.com/runetfreedom/russia-v2ray-rules-dat) (та же база, что в karing-ruleset/russia). Обновляются автоматически каждый день через GitHub Actions.

| Файл | Тип | Что внутри | Политика |
|---|---|---|---|
| `lists/ads.list` | DOMAIN-SET | geosite category-ads-all | REJECT |
| `lists/ru-blocked.list` | DOMAIN-SET | geosite ru-blocked | VPN |
| `lists/ru-direct.list` | DOMAIN-SET | geosite category-ru + ru-available-only-inside | DIRECT |
| `lists/ru-blocked-ip.list` | RULE-SET | geoip ru-blocked внутри российских сетей + ru-blocked-community | VPN |
| `lists/ru-ip.list` | RULE-SET | geoip ru | DIRECT |

Готовый конфиг: `notpubli.cc_VPN.conf`.
