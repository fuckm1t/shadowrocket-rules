#!/usr/bin/env python3
"""Конвертация rule-set sing-box (runetfreedom, после decompile в JSON) в списки Shadowrocket.

Использование: convert.py <папка с json> <папка вывода>
"""
import ipaddress
import json
import sys
from pathlib import Path

SRC = Path(sys.argv[1])
OUT = Path(sys.argv[2])
OUT.mkdir(parents=True, exist_ok=True)


def load(name):
    data = json.loads((SRC / f"{name}.json").read_text(encoding="utf-8"))
    res = {"domain": set(), "domain_suffix": set(), "ip_cidr": set()}
    for rule in data["rules"]:
        for key in res:
            val = rule.get(key, [])
            res[key].update([val] if isinstance(val, str) else val)
    return res


def header(title, source, count):
    return [
        f"# {title}",
        f"# Источник: runetfreedom/russia-v2ray-rules-dat ({source})",
        f"# Записей: {count}",
    ]


def domain_set(fname, title, names):
    """DOMAIN-SET: '.example.com' - домен и поддомены, 'example.com' - только точное совпадение."""
    suffixes, exact = set(), set()
    for n in names:
        r = load(n)
        suffixes |= {d.strip(".").lower() for d in r["domain_suffix"] if d.strip(".")}
        exact |= {d.lower() for d in r["domain"]}
    # убрать то, что уже покрыто более общим суффиксом
    def covered(d):
        parts = d.split(".")
        return any(".".join(parts[i:]) in suffixes for i in range(1, len(parts)))
    suffixes = {d for d in suffixes if not covered(d)}
    exact = {d for d in exact if d not in suffixes and not covered(d)}
    lines = sorted("." + d for d in suffixes) + sorted(exact)
    (OUT / fname).write_text("\n".join(header(title, ", ".join(names), len(lines)) + lines) + "\n", encoding="utf-8")
    return len(lines)


def nets(name):
    return [ipaddress.ip_network(c, strict=False) for c in load(name)["ip_cidr"]]


def ip_rule_set(fname, title, source, networks):
    networks = list(ipaddress.collapse_addresses([n for n in networks if n.version == 4])) + \
        list(ipaddress.collapse_addresses([n for n in networks if n.version == 6]))
    lines = [f"IP-CIDR,{n}" if n.version == 4 else f"IP-CIDR6,{n}" for n in networks]
    (OUT / fname).write_text("\n".join(header(title, source, len(lines)) + lines) + "\n", encoding="utf-8")
    return len(lines)


def intersect(a, b):
    """Пересечение двух наборов сетей (одной версии IP)."""
    out = []
    b_sorted = sorted(b, key=lambda n: (n.version, n.network_address))
    for x in a:
        for y in b_sorted:
            if x.version != y.version:
                continue
            if x.subnet_of(y):
                out.append(x)
            elif y.subnet_of(x):
                out.append(y)
    return out


stats = {}
stats["ru-direct.list"] = domain_set(
    "ru-direct.list", "Российские сервисы - DIRECT",
    ["geosite-category-ru", "geosite-ru-available-only-inside"])
stats["ru-blocked.list"] = domain_set(
    "ru-blocked.list", "Заблокированные в РФ домены - через VPN", ["geosite-ru-blocked"])
stats["ru-ip.list"] = ip_rule_set(
    "ru-ip.list", "IP-адреса РФ - DIRECT", "geoip-ru", nets("geoip-ru"))

# Заблокированные IP: полный список огромный, а зарубежные адреса и так уходят в VPN по FINAL.
# Оставляем только ту часть, что попала бы в DIRECT по российским IP, плюс community-список.
ru = list(ipaddress.collapse_addresses([n for n in nets("geoip-ru") if n.version == 4])) + \
    list(ipaddress.collapse_addresses([n for n in nets("geoip-ru") if n.version == 6]))
blocked_in_ru = []
for ver in (4, 6):
    bl = list(ipaddress.collapse_addresses([n for n in nets("geoip-ru-blocked") if n.version == ver]))
    rv = [n for n in ru if n.version == ver]
    # быстрый проход по отсортированным интервалам
    i = j = 0
    while i < len(bl) and j < len(rv):
        a, b = bl[i], rv[j]
        if a.subnet_of(b):
            blocked_in_ru.append(a); i += 1
        elif b.subnet_of(a):
            blocked_in_ru.append(b); j += 1
        elif a.network_address < b.network_address:
            i += 1
        else:
            j += 1
stats["ru-blocked-ip.list"] = ip_rule_set(
    "ru-blocked-ip.list", "Заблокированные IP внутри российских сетей + community - через VPN",
    "geoip-ru-blocked ∩ geoip-ru, geoip-ru-blocked-community",
    blocked_in_ru + nets("geoip-ru-blocked-community"))

for k, v in stats.items():
    print(f"{k}: {v}")
