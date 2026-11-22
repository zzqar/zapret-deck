"""
Смоук-тест бэкенда без Steam Deck.

Заглушка decky содержит ровно те атрибуты, что экспортирует настоящий модуль
decky (decky-loader, backend/decky_loader/plugin/imports/decky.py), поэтому
обращение к несуществующему decky.X упадёт здесь так же, как на Deck.

Запуск: python3 tests/smoke.py
"""
import asyncio
import logging
import os
import sys
import tempfile
import time
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
tmp = tempfile.mkdtemp()

decky = types.ModuleType("decky")
for name, value in {
    "DECKY_VERSION": "v3.0.0",
    "DECKY_USER": "nobody",
    "DECKY_USER_HOME": tmp,
    "DECKY_HOME": tmp,
    "DECKY_PLUGIN_SETTINGS_DIR": os.path.join(tmp, "settings"),
    "DECKY_PLUGIN_RUNTIME_DIR": os.path.join(tmp, "data"),
    "DECKY_PLUGIN_LOG_DIR": os.path.join(tmp, "logs"),
    "DECKY_PLUGIN_DIR": ROOT,
    "DECKY_PLUGIN_NAME": "Zapret Deck",
    "DECKY_PLUGIN_VERSION": "0.0.0",
    "DECKY_PLUGIN_AUTHOR": "test",
    "DECKY_PLUGIN_LOG": os.path.join(tmp, "logs", "plugin.log"),
}.items():
    setattr(decky, name, value)
logging.basicConfig(level=logging.INFO, format="  log: %(message)s")
decky.logger = logging.getLogger()


async def _emit(event, *args):
    pass


decky.emit = _emit
sys.modules["decky"] = decky
sys.path.insert(0, ROOT)

import main  # noqa: E402

main.DEFAULT_SETTINGS["autostart"] = False


async def run():
    # api_version 1: экземпляр
    p = main.Plugin()
    await p._main()
    t0 = time.perf_counter()
    st = await p.get_state()
    assert not st["error"], st["error"]
    assert st["strategies"], "нет стратегий"
    print(f"get_state (экземпляр): {1000 * (time.perf_counter() - t0):.1f} ms, "
          f"{len(st['strategies'])} стратегий, списки: {[l['id'] for l in st['lists']]}")
    assert (await p.set_autostart(True))["ok"]
    assert (await p.set_strategy("vn-01.conf"))["ok"]
    # api_version 0: методы на классе
    st = await main.Plugin.get_state(main.Plugin)
    assert st["strategy"] == "vn-01.conf"
    print("get_state (класс): ok")
    assert os.path.isfile(main.SETTINGS_FILE), "настройки не сохранились"
    # подменённый nfqws не должен запускаться
    os.makedirs(main.ROOT_BIN_DIR, exist_ok=True)
    with open(main.NFQWS, "wb") as f:
        f.write(b"not nfqws")
    try:
        main._impl._verify_nfqws()
        raise AssertionError("подменённый nfqws прошёл проверку")
    except RuntimeError as e:
        print(f"подмена nfqws обнаружена: {e}")
    print("OK")


asyncio.run(run())
