"""
Zapret Deck — backend плагина Decky Loader.

Запускает nfqws с выбранной стратегией и отправляет трафик
в NFQUEUE через nftables (или iptables). Параллельно может поднять локальный
DNS-over-TLS резолвер: во Вьетнаме провайдер подменяет DNS-ответы на 127.0.0.1.
"""

import asyncio
import hashlib
import json
import os
import pwd
import re
import shlex
import shutil
import subprocess
import sys
import tarfile

import decky

PLUGIN_DIR = decky.DECKY_PLUGIN_DIR
sys.path.insert(0, os.path.join(PLUGIN_DIR, "py_modules"))
import dns_proxy  # noqa: E402

DATA_DIR = os.path.join(decky.DECKY_USER_HOME, "zapret-deck")
STRAT_DIR = os.path.join(DATA_DIR, "strategies")
LISTS_DIR = os.path.join(DATA_DIR, "lists")
FAKE_DIR = os.path.join(DATA_DIR, "fake")
# Бинарник запускается от root, поэтому лежит в папке Decky, принадлежащей root,
# а не в ~/zapret-deck, куда может писать любой процесс пользователя deck.
ROOT_BIN_DIR = os.path.join(decky.DECKY_PLUGIN_RUNTIME_DIR, "bin")
NFQWS = os.path.join(ROOT_BIN_DIR, "nfqws")

# Рабочая копия списков и fake-файлов: nfqws по умолчанию сбрасывает
# привилегии, а /home/deck закрыт для чужих пользователей.
RUN_DIR = "/run/zapret-deck"
LOG_FILE = os.path.join(decky.DECKY_PLUGIN_LOG_DIR, "nfqws.log")
SETTINGS_FILE = os.path.join(decky.DECKY_PLUGIN_SETTINGS_DIR, "settings.json")

QNUM = 200
MARK = "0x40000000"
NFT_TABLE = "zapret_deck"
IPT_CHAIN = "ZAPRET_DECK"
# nfqws закреплён на конкретной версии. Архив и сам бинарник сверяются с SHA-256:
# подменённый релиз или файл на диске не будут запущены.
NFQWS_VERSION = "v72.13"
NFQWS_URL = (
    f"https://github.com/bol-van/zapret/releases/download/{NFQWS_VERSION}/zapret-{NFQWS_VERSION}.tar.gz"
)
NFQWS_ARCHIVE_SHA256 = "25c74e6c5f48963fa244c2955e76694a07c39447245a0457e2efdc74b3317e68"
NFQWS_BIN_SHA256 = "f34615964d7321650197cd69d3f7cbfdaabe8118b5a0d57c6e41dccdff658999"
NFQWS_MEMBER = f"zapret-{NFQWS_VERSION}/binaries/linux-x86_64/nfqws"

EXCLUDE_LIST = "exclude.txt"
AUTO_LIST = "autohostlist.txt"
SPECIAL_LISTS = {EXCLUDE_LIST, AUTO_LIST}

DEFAULT_SETTINGS = {
    "enabled": False,
    "dns": True,
    "autostart": True,
    "strategy": "00-vietnam-fpt.conf",
    "lists": ["vietnam.txt"],
}

PORTS_RE = re.compile(r"^[0-9,\-]*$")


def clean_env() -> dict:
    """Decky собран PyInstaller'ом и подсовывает свои библиотеки, из-за
    чего системные nft, iptables, curl и nmcli не запускаются."""
    env = dict(os.environ)
    for key in ("LD_LIBRARY_PATH", "LD_PRELOAD", "PYTHONHOME", "PYTHONPATH"):
        env.pop(key, None)
    env["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    return env


def run(cmd, input_text=None, timeout=30, check=False) -> subprocess.CompletedProcess:
    res = subprocess.run(
        cmd, input=input_text, capture_output=True, text=True, timeout=timeout, env=clean_env()
    )
    if check and res.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)}: {res.stderr.strip() or res.stdout.strip()}")
    return res


def which(name: str):
    return shutil.which(name, path=clean_env()["PATH"])


def chown_user(path: str):
    try:
        pw = pwd.getpwnam(decky.DECKY_USER)
    except KeyError:
        return
    for root, dirs, files in os.walk(path):
        for item in [root, *(os.path.join(root, n) for n in dirs + files)]:
            try:
                os.chown(item, pw.pw_uid, pw.pw_gid)
            except OSError:
                pass


def bundled_dir(name: str):
    """decky-cli кладёт содержимое defaults/ в корень плагина, а ручной
    деплой оставляет папку defaults/. Поддерживаем оба варианта."""
    for candidate in (os.path.join(PLUGIN_DIR, name), os.path.join(PLUGIN_DIR, "defaults", name)):
        if os.path.isdir(candidate):
            return candidate
    return None


def tail(path: str, lines: int = 30) -> str:
    try:
        with open(path, "r", errors="replace") as f:
            return "".join(f.readlines()[-lines:])
    except OSError:
        return ""


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def count_domains(path: str) -> int:
    try:
        with open(path, errors="replace") as f:
            return sum(1 for l in f if l.strip() and not l.lstrip().startswith("#"))
    except OSError:
        return 0


def parse_strategy(path: str) -> dict:
    meta = {
        "id": os.path.basename(path),
        "name": os.path.splitext(os.path.basename(path))[0],
        "description": "",
        "tcp": "80,443",
        "udp": "443",
    }
    body = []
    with open(path, "r", errors="replace") as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            if line.startswith("#"):
                m = re.match(r"#\s*(\w+)\s*:\s*(.*)$", line)
                if m and m.group(1).lower() in ("name", "description", "tcp", "udp"):
                    meta[m.group(1).lower()] = m.group(2).strip()
                continue
            body.append(line)
    for key in ("tcp", "udp"):
        meta[key] = meta[key].replace(" ", "")
        if not PORTS_RE.match(meta[key]):
            raise ValueError(f"{meta['id']}: некорректные порты '{meta[key]}'")
    meta["args"] = " ".join(body)
    return meta


class ZapretDeck:
    proc = None
    log_fh = None
    fw_backend = None
    last_error = ""
    dns_error = ""
    lock = None
    settings = None
    dns = None
    dns_task = None
    modprobed = False
    init_error = ""

    # ---------- настройки и файлы ----------

    def _load_settings(self):
        s = dict(DEFAULT_SETTINGS)
        try:
            with open(SETTINGS_FILE) as f:
                s.update(json.load(f))
        except (OSError, ValueError):
            pass
        self.settings = s

    def _save_settings(self):
        os.makedirs(os.path.dirname(SETTINGS_FILE), exist_ok=True)
        with open(SETTINGS_FILE, "w") as f:
            json.dump(self.settings, f, indent=2, ensure_ascii=False)

    def _seed_data_dir(self):
        """Копирует встроенные стратегии, списки и fake-файлы в ~/zapret-deck.
        Уже существующие файлы не трогает, вдруг пользователь их отредактировал."""
        for sub, dst in (("strategies", STRAT_DIR), ("lists", LISTS_DIR), ("fake", FAKE_DIR)):
            os.makedirs(dst, exist_ok=True)
            src = bundled_dir(sub)
            if not src:
                continue
            for name in os.listdir(src):
                target = os.path.join(dst, name)
                if not os.path.exists(target):
                    shutil.copy2(os.path.join(src, name), target)
        # nfqws из старых версий лежал в ~/zapret-deck/bin, теперь он в папке root
        shutil.rmtree(os.path.join(DATA_DIR, "bin"), ignore_errors=True)
        auto = os.path.join(LISTS_DIR, AUTO_LIST)
        if not os.path.exists(auto):
            open(auto, "w").close()
        chown_user(DATA_DIR)

    def _strategies(self):
        result = []
        for name in sorted(os.listdir(STRAT_DIR)):
            if not name.endswith(".conf"):
                continue
            try:
                result.append(parse_strategy(os.path.join(STRAT_DIR, name)))
            except (OSError, ValueError) as e:
                decky.logger.warning(f"Стратегия {name} пропущена: {e}")
        return result

    def _lists(self):
        return [
            {
                "id": name,
                "enabled": name in self.settings["lists"],
                "count": count_domains(os.path.join(LISTS_DIR, name)),
            }
            for name in sorted(os.listdir(LISTS_DIR))
            if name.endswith(".txt") and name not in SPECIAL_LISTS
        ]

    def _nfqws_path(self):
        return NFQWS if os.path.isfile(NFQWS) else None

    def _verify_nfqws(self):
        """Сверяет бинарник с закреплённым хешем перед каждым запуском."""
        st = os.stat(NFQWS)
        if st.st_uid != 0 or st.st_mode & 0o022:
            raise RuntimeError("nfqws доступен на запись не только root — переустановите nfqws")
        actual = sha256_file(NFQWS)
        if actual != NFQWS_BIN_SHA256:
            raise RuntimeError(
                f"SHA-256 nfqws не совпадает ({actual[:12]}…), запуск отменён. Переустановите nfqws"
            )

    # ---------- firewall ----------

    def _detect_fw(self):
        if which("nft"):
            return "nft"
        if which("iptables"):
            return "iptables"
        return None

    def _fw_apply(self, tcp: str, udp: str, incoming: bool):
        """incoming=True дополнительно отправляет в очередь первые входящие
        TCP-пакеты. Без них autohostlist не видит RST и редиректы от DPI.
        Старые правила к этому моменту уже удалены в _stop()."""
        backend = self._detect_fw()
        if backend is None:
            raise RuntimeError("Не найден ни nft, ни iptables")
        out_pkts = "1-9" if incoming else "1-6"
        if backend == "nft":
            rules = [
                f"table inet {NFT_TABLE} {{",
                "  chain post {",
                "    type filter hook postrouting priority mangle; policy accept;",
            ]
            for proto, ports in (("tcp", tcp), ("udp", udp)):
                if ports:
                    rules.append(
                        f"    meta mark and {MARK} == 0 {proto} dport {{ {ports} }} "
                        f"ct original packets {out_pkts} queue num {QNUM} bypass"
                    )
            rules.append("  }")
            if incoming and tcp:
                rules += [
                    "  chain pre {",
                    "    type filter hook prerouting priority filter; policy accept;",
                    f"    tcp sport {{ {tcp} }} ct reply packets 1-3 queue num {QNUM} bypass",
                    "  }",
                ]
            rules.append("}")
            run(["nft", "-f", "-"], input_text="\n".join(rules) + "\n", check=True)
        else:
            for ipt in ("iptables", "ip6tables"):
                if not which(ipt):
                    continue
                for chain in (IPT_CHAIN, IPT_CHAIN + "_IN"):
                    run([ipt, "-t", "mangle", "-N", chain])
                    run([ipt, "-t", "mangle", "-F", chain], check=True)
                for proto, ports in (("tcp", tcp), ("udp", udp)):
                    if not ports:
                        continue
                    run([
                        ipt, "-t", "mangle", "-A", IPT_CHAIN, "-p", proto,
                        "-m", "multiport", "--dports", ports.replace("-", ":"),
                        "-m", "connbytes", "--connbytes-dir=original",
                        "--connbytes-mode=packets", "--connbytes", out_pkts.replace("-", ":"),
                        "-m", "mark", "!", "--mark", f"{MARK}/{MARK}",
                        "-j", "NFQUEUE", "--queue-num", str(QNUM), "--queue-bypass",
                    ], check=True)
                run([ipt, "-t", "mangle", "-I", "POSTROUTING", "-j", IPT_CHAIN], check=True)
                if incoming and tcp:
                    run([
                        ipt, "-t", "mangle", "-A", IPT_CHAIN + "_IN", "-p", "tcp",
                        "-m", "multiport", "--sports", tcp.replace("-", ":"),
                        "-m", "connbytes", "--connbytes-dir=reply",
                        "--connbytes-mode=packets", "--connbytes", "1:3",
                        "-j", "NFQUEUE", "--queue-num", str(QNUM), "--queue-bypass",
                    ], check=True)
                    run([ipt, "-t", "mangle", "-I", "PREROUTING", "-j", IPT_CHAIN + "_IN"], check=True)
        self.fw_backend = backend

    def _fw_remove(self):
        """Чистит только то, что реально есть: на SteamOS это обычно одна
        таблица nft, а не 16 вызовов iptables."""
        if which("nft"):
            run(["nft", "delete", "table", "inet", NFT_TABLE])
        for ipt in ("iptables", "ip6tables"):
            if not which(ipt):
                continue
            if run([ipt, "-t", "mangle", "-n", "-L", IPT_CHAIN]).returncode != 0:
                continue
            for hook, chain in (("POSTROUTING", IPT_CHAIN), ("PREROUTING", IPT_CHAIN + "_IN")):
                for _ in range(10):
                    if run([ipt, "-t", "mangle", "-D", hook, "-j", chain]).returncode != 0:
                        break
                run([ipt, "-t", "mangle", "-F", chain])
                run([ipt, "-t", "mangle", "-X", chain])
        self.fw_backend = None

    # ---------- nfqws ----------

    def _is_running(self) -> bool:
        return self.proc is not None and self.proc.returncode is None

    def _stage_runtime(self):
        """Копирует включённые списки, exclude, autohostlist и fake-файлы
        в /run/zapret-deck."""
        if os.path.isdir(RUN_DIR):
            shutil.rmtree(RUN_DIR, ignore_errors=True)
        os.makedirs(os.path.join(RUN_DIR, "lists"), mode=0o755)
        os.makedirs(os.path.join(RUN_DIR, "fake"), mode=0o755)
        os.chmod(RUN_DIR, 0o755)

        def stage(src, dst, mode=0o644):
            shutil.copyfile(src, dst)
            os.chmod(dst, mode)

        lists = []
        for name in self.settings["lists"]:
            src = os.path.join(LISTS_DIR, name)
            if os.path.isfile(src) and name not in SPECIAL_LISTS:
                dst = os.path.join(RUN_DIR, "lists", name)
                stage(src, dst)
                lists.append(dst)
        for name in SPECIAL_LISTS:
            src = os.path.join(LISTS_DIR, name)
            if os.path.isfile(src):
                # в autohostlist пишет сам nfqws, поэтому файл должен быть доступен на запись
                stage(src, os.path.join(RUN_DIR, "lists", name), 0o666 if name == AUTO_LIST else 0o644)
        for name in os.listdir(FAKE_DIR):
            stage(os.path.join(FAKE_DIR, name), os.path.join(RUN_DIR, "fake", name))
        return lists

    def _save_autohostlist(self):
        src = os.path.join(RUN_DIR, "lists", AUTO_LIST)
        if os.path.isfile(src):
            dst = os.path.join(LISTS_DIR, AUTO_LIST)
            shutil.copyfile(src, dst)
            chown_user(dst)

    def _build_args(self, strategy: dict, lists: list) -> list:
        rl = os.path.join(RUN_DIR, "lists")
        fake = os.path.join(RUN_DIR, "fake")
        exclude = os.path.join(rl, EXCLUDE_LIST)
        subs = {
            "{hostlist}": " ".join(f"--hostlist={p}" for p in lists),
            "{exclude}": f"--hostlist-exclude={exclude}" if os.path.isfile(exclude) else "",
            "{autohostlist}": f"--hostlist-auto={os.path.join(rl, AUTO_LIST)}",
            "{fake_quic}": os.path.join(fake, "quic_initial_www_google_com.bin"),
            "{fake_tls}": os.path.join(fake, "tls_clienthello_www_google_com.bin"),
            "{lists_dir}": rl,
        }
        args = strategy["args"]
        for key, value in subs.items():
            args = args.replace(key, value)
        return shlex.split(args)

    async def _start(self):
        await self._stop()
        self.last_error = ""
        nfqws = self._nfqws_path()
        if not nfqws:
            raise RuntimeError("nfqws не установлен — нажмите «Скачать nfqws»")
        await asyncio.to_thread(self._verify_nfqws)
        strategies = {s["id"]: s for s in self._strategies()}
        strategy = strategies.get(self.settings["strategy"])
        if strategy is None:
            raise RuntimeError(f"Стратегия {self.settings['strategy']} не найдена")

        if not self.modprobed:
            await asyncio.to_thread(run, ["modprobe", "nfnetlink_queue"])
            self.modprobed = True
        lists = self._stage_runtime()
        cmd = [nfqws, f"--qnum={QNUM}", f"--dpi-desync-fwmark={MARK}", *self._build_args(strategy, lists)]
        pretty = " ".join(shlex.quote(c) for c in cmd)
        decky.logger.info("Запуск: " + pretty)

        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        self.log_fh = open(LOG_FILE, "w")
        self.log_fh.write(f"$ {pretty}\n")
        self.log_fh.flush()
        self.proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=self.log_fh, stderr=subprocess.STDOUT, env=clean_env()
        )
        try:
            # Правила ставим сразу: из-за bypass трафик не пострадает, даже если nfqws не поднимется
            await asyncio.to_thread(
                self._fw_apply, strategy["tcp"], strategy["udp"], "{autohostlist}" in strategy["args"]
            )
        except Exception:
            await self._stop()
            raise
        # Неверные аргументы nfqws отвергает за миллисекунды, долго ждать не нужно
        try:
            await asyncio.wait_for(asyncio.shield(self.proc.wait()), 0.4)
        except asyncio.TimeoutError:
            return
        log = tail(LOG_FILE, 15)
        await self._stop()
        raise RuntimeError(f"nfqws завершился сразу после запуска:\n{log}")

    async def _stop(self):
        try:
            await asyncio.to_thread(self._fw_remove)
        except Exception as e:
            decky.logger.warning(f"Очистка firewall: {e}")
        if self._is_running():
            self.proc.terminate()
            try:
                await asyncio.wait_for(self.proc.wait(), 5)
            except asyncio.TimeoutError:
                self.proc.kill()
                await self.proc.wait()
        if self.proc is not None:
            try:
                self._save_autohostlist()
            except OSError as e:
                decky.logger.warning(f"autohostlist: {e}")
        self.proc = None
        if self.log_fh:
            self.log_fh.close()
            self.log_fh = None

    async def _apply(self):
        """Приводит состояние процесса к settings['enabled']."""
        async with self.lock:
            try:
                if self.settings["enabled"]:
                    await self._start()
                else:
                    await self._stop()
                return {"ok": True}
            except Exception as e:
                self.last_error = str(e)
                decky.logger.error(f"Ошибка: {e}")
                return {"ok": False, "error": str(e)}

    # ---------- DNS-over-TLS ----------

    def _nm_devices(self):
        res = run(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "device"], check=True)
        devs = []
        for line in res.stdout.splitlines():
            parts = line.split(":")
            if len(parts) >= 3 and parts[1] in ("wifi", "ethernet") and parts[2].startswith("connected"):
                devs.append(parts[0])
        return devs

    def _nm_point_to_proxy(self):
        """Временно (без изменения профилей) переключает DNS активных
        подключений на наш прокси. Если подключиться к другой сети, настройка
        слетит, поэтому вызывается периодически из _dns_watch."""
        for dev in self._nm_devices():
            current = run(["nmcli", "-g", "IP4.DNS", "device", "show", dev]).stdout
            if current.strip().split(" | ") == [dns_proxy.LISTEN_ADDR]:
                continue
            run([
                "nmcli", "device", "modify", dev,
                "ipv4.dns", dns_proxy.LISTEN_ADDR, "ipv4.ignore-auto-dns", "yes",
                "ipv6.ignore-auto-dns", "yes",
            ], check=True)
            decky.logger.info(f"DNS {dev} → {dns_proxy.LISTEN_ADDR}")

    def _nm_restore(self):
        try:
            for dev in self._nm_devices():
                run(["nmcli", "device", "reapply", dev])
        except Exception as e:
            decky.logger.warning(f"Восстановление DNS: {e}")

    async def _dns_watch(self):
        while True:
            await asyncio.sleep(20)
            try:
                await asyncio.to_thread(self._nm_point_to_proxy)
            except Exception as e:
                self.dns_error = str(e)

    async def _dns_start(self):
        await self._dns_stop()
        self.dns_error = ""
        if not which("nmcli"):
            raise RuntimeError("nmcli не найден, DNS нельзя переключить")
        self.dns = dns_proxy.DnsProxy(decky.logger)
        try:
            await asyncio.gather(self.dns.start(), asyncio.to_thread(self._nm_point_to_proxy))
        except Exception:
            await self._dns_stop()
            raise
        self.dns_task = asyncio.ensure_future(self._dns_watch())

    async def _dns_stop(self):
        if self.dns_task:
            self.dns_task.cancel()
            self.dns_task = None
        if self.dns:
            await asyncio.to_thread(self._nm_restore)
            await self.dns.stop()
            self.dns = None

    async def _apply_dns(self):
        try:
            if self.settings["dns"]:
                await self._dns_start()
            else:
                await self._dns_stop()
            return {"ok": True}
        except Exception as e:
            self.dns_error = str(e)
            decky.logger.error(f"DNS: {e}")
            return {"ok": False, "error": f"DNS: {e}"}

    # ---------- API для frontend ----------

    async def get_state(self):
        try:
            return await self._get_state()
        except Exception as e:
            decky.logger.exception("get_state")
            # отдаём UI хоть что-то, чтобы он показал ошибку, а не висел на «Загрузка…»
            return {
                "running": False, "enabled": False, "dns": False, "dns_running": False,
                "dns_error": "", "autostart": False, "strategy": "", "strategies": [],
                "lists": [], "auto_count": 0, "nfqws_installed": False, "firewall": None,
                "error": f"{self.init_error or ''}\nget_state: {type(e).__name__}: {e}".strip(),
                "data_dir": DATA_DIR,
            }

    async def _get_state(self):
        if self.settings is None:
            self._load_settings()
        if self.settings["enabled"] and self.proc is not None and not self._is_running():
            self.last_error = f"nfqws упал (код {self.proc.returncode}):\n{tail(LOG_FILE, 15)}"
            async with self.lock:
                await self._stop()
        return {
            "running": self._is_running(),
            "enabled": self.settings["enabled"],
            "dns": self.settings["dns"],
            "dns_running": self.dns is not None,
            "dns_error": self.dns_error,
            "autostart": self.settings["autostart"],
            "strategy": self.settings["strategy"],
            "strategies": [
                {"id": s["id"], "name": s["name"], "description": s["description"]}
                for s in self._strategies()
            ],
            "lists": self._lists(),
            "auto_count": count_domains(os.path.join(
                RUN_DIR if self._is_running() else DATA_DIR, "lists", AUTO_LIST)),
            "nfqws_installed": self._nfqws_path() is not None,
            "firewall": self.fw_backend or self._detect_fw(),
            "error": self.last_error,
            "data_dir": DATA_DIR,
        }

    async def set_enabled(self, enabled: bool):
        self.settings["enabled"] = bool(enabled)
        self._save_settings()
        res = await self._apply()
        if not res["ok"]:
            self.settings["enabled"] = False
            self._save_settings()
        return res

    async def set_dns(self, enabled: bool):
        self.settings["dns"] = bool(enabled)
        self._save_settings()
        res = await self._apply_dns()
        if not res["ok"]:
            self.settings["dns"] = False
            self._save_settings()
        return res

    async def set_strategy(self, strategy_id: str):
        self.settings["strategy"] = strategy_id
        self._save_settings()
        return await self._apply() if self.settings["enabled"] else {"ok": True}

    async def set_list(self, list_id: str, enabled: bool):
        lists = [l for l in self.settings["lists"] if l != list_id]
        if enabled:
            lists.append(list_id)
        self.settings["lists"] = lists
        self._save_settings()
        return await self._apply() if self.settings["enabled"] else {"ok": True}

    async def set_autostart(self, enabled: bool):
        self.settings["autostart"] = bool(enabled)
        self._save_settings()
        return {"ok": True}

    async def restart(self):
        return await self._apply()

    async def clear_autohostlist(self):
        for base in (DATA_DIR, RUN_DIR):
            path = os.path.join(base, "lists", AUTO_LIST)
            if os.path.isfile(path):
                open(path, "w").close()
        return await self._apply() if self.settings["enabled"] else {"ok": True}

    async def get_log(self):
        return tail(LOG_FILE, 40)

    async def check_url(self, url: str):
        """Проверка доступности сайта через системный curl (идёт через
        системный DNS и nfqws, то есть так же, как Steam)."""
        def _check():
            res = run(
                ["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code} %{time_total} %{remote_ip}",
                 "-A", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/140.0.0.0 Safari/537.36",
                 "--max-time", "10", url],
                timeout=15,
            )
            parts = res.stdout.split()
            ip = parts[2] if len(parts) > 2 else ""
            if ip.startswith("127.") or ip == "0.0.0.0":
                return {"ok": False, "url": url, "error": f"DNS подменён → {ip}. Включите защищённый DNS"}
            if res.returncode != 0:
                return {"ok": False, "url": url, "error": res.stderr.strip() or f"curl код {res.returncode}"}
            return {"ok": parts[0] != "000", "url": url, "code": int(parts[0]),
                    "time": float(parts[1]), "ip": ip}
        try:
            return await asyncio.to_thread(_check)
        except Exception as e:
            return {"ok": False, "url": url, "error": str(e)}

    async def install_nfqws(self):
        """Скачивает закреплённую версию, сверяет SHA-256 архива и бинарника
        и ставит nfqws в папку root. Fake-файлы уже входят в плагин."""
        def _install():
            os.makedirs(ROOT_BIN_DIR, mode=0o755, exist_ok=True)
            os.chown(ROOT_BIN_DIR, 0, 0)
            os.chmod(ROOT_BIN_DIR, 0o755)
            archive = os.path.join(ROOT_BIN_DIR, "download.tar.gz")
            try:
                run(["curl", "-fsSL", "--max-time", "180", "-o", archive, NFQWS_URL],
                    timeout=200, check=True)
                actual = sha256_file(archive)
                if actual != NFQWS_ARCHIVE_SHA256:
                    raise RuntimeError(
                        f"SHA-256 архива не совпадает ({actual[:12]}…): файл подменён или повреждён"
                    )
                with tarfile.open(archive, "r:gz") as tar:
                    data = tar.extractfile(tar.getmember(NFQWS_MEMBER)).read()
            finally:
                if os.path.exists(archive):
                    os.remove(archive)
            if hashlib.sha256(data).hexdigest() != NFQWS_BIN_SHA256:
                raise RuntimeError("SHA-256 nfqws в архиве не совпадает")
            tmp = NFQWS + ".new"
            with open(tmp, "wb") as f:
                f.write(data)
            os.chown(tmp, 0, 0)
            os.chmod(tmp, 0o755)
            os.replace(tmp, NFQWS)
            return {"ok": True, "version": NFQWS_VERSION}
        try:
            return await asyncio.to_thread(_install)
        except Exception as e:
            decky.logger.error(f"Установка nfqws: {e}")
            return {"ok": False, "error": str(e)}

    # ---------- жизненный цикл ----------

    async def _main(self):
        decky.logger.info(f"Zapret Deck: старт, python {sys.version.split()[0]}, uid {os.getuid()}, "
                          f"plugin_dir {PLUGIN_DIR}, data_dir {DATA_DIR}")
        self.lock = asyncio.Lock()
        self._load_settings()
        try:
            self._seed_data_dir()
        except Exception as e:
            self.init_error = f"Не удалось подготовить {DATA_DIR}: {e}"
            decky.logger.exception("seed")
            return
        decky.logger.info(f"Настройки: {self.settings}")
        if self.settings["autostart"]:
            jobs = []
            if self.settings["dns"]:
                jobs.append(self._apply_dns())
            if self.settings["enabled"]:
                jobs.append(self._apply())
            if jobs:
                await self._wait_network()
                t0 = asyncio.get_running_loop().time()
                await asyncio.gather(*jobs)
                decky.logger.info(f"Автозапуск занял {asyncio.get_running_loop().time() - t0:.2f} с")
        else:
            self.settings["enabled"] = False
            self.settings["dns"] = False
            self._save_settings()
        decky.logger.info("Zapret Deck загружен")

    async def _wait_network(self, timeout: float = 15):
        """После загрузки Deck ждём, пока NetworkManager поднимет сеть
        (обычно это уже сделано, тогда ожидания нет)."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            try:
                res = await asyncio.to_thread(run, ["nmcli", "-t", "-f", "STATE", "general"], None, 3)
                if res.stdout.strip().startswith("connected"):
                    return
            except Exception:
                return
            await asyncio.sleep(0.5)

    async def _unload(self):
        if self.lock:
            async with self.lock:
                await self._stop()
        await self._dns_stop()
        decky.logger.info("Zapret Deck выгружен")

    async def _uninstall(self):
        await self._stop()
        await self._dns_stop()
        shutil.rmtree(RUN_DIR, ignore_errors=True)


# При api_version 1 Decky создаёт экземпляр Plugin(), при api_version 0 вызывает
# методы на классе. Логика живёт в одном экземпляре ZapretDeck, а Plugin только
# пересылает вызовы, поэтому работают оба варианта.
_impl = ZapretDeck()


class Plugin:
    async def get_state(self):
        return await _impl.get_state()

    async def set_enabled(self, enabled: bool):
        return await _impl.set_enabled(enabled)

    async def set_dns(self, enabled: bool):
        return await _impl.set_dns(enabled)

    async def set_strategy(self, strategy_id: str):
        return await _impl.set_strategy(strategy_id)

    async def set_list(self, list_id: str, enabled: bool):
        return await _impl.set_list(list_id, enabled)

    async def set_autostart(self, enabled: bool):
        return await _impl.set_autostart(enabled)

    async def restart(self):
        return await _impl.restart()

    async def clear_autohostlist(self):
        return await _impl.clear_autohostlist()

    async def get_log(self):
        return await _impl.get_log()

    async def check_url(self, url: str):
        return await _impl.check_url(url)

    async def install_nfqws(self):
        return await _impl.install_nfqws()

    async def _main(self):
        return await _impl._main()

    async def _unload(self):
        return await _impl._unload()

    async def _uninstall(self):
        return await _impl._uninstall()
