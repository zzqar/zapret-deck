"""
Локальный DNS-резолвер, который пересылает запросы по DNS-over-TLS (порт 853).

Провайдеры во Вьетнаме подменяют ответы обычного DNS (Steam → 127.0.0.1)
и глушат запросы на 53 порт. DoT они не трогают, поэтому слушаем на
127.0.0.77:53 (UDP+TCP) и шифруем всё до 1.1.1.1 / 8.8.8.8.
"""

import asyncio
import os
import ssl
import struct

LISTEN_ADDR = "127.0.0.77"
LISTEN_PORT = 53
UPSTREAMS = [
    ("1.1.1.1", "cloudflare-dns.com"),
    ("8.8.8.8", "dns.google"),
    ("1.0.0.1", "cloudflare-dns.com"),
    ("8.8.4.4", "dns.google"),
]
# Decky собран PyInstaller'ом, поэтому системный CA-бандл указываем явно
CA_FILES = [
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/ca-certificates/extracted/tls-ca-bundle.pem",
]
POOL_SIZE = 4
TIMEOUT = 5
CONNECT_TIMEOUT = 3


def _ssl_context() -> ssl.SSLContext:
    for path in CA_FILES:
        if os.path.exists(path):
            return ssl.create_default_context(cafile=path)
    return ssl.create_default_context()


class _DotConn:
    def __init__(self, ctx: ssl.SSLContext):
        self.ctx = ctx
        self.lock = asyncio.Lock()
        self.reader = None
        self.writer = None
        self.upstream = 0

    def _close(self):
        if self.writer is not None:
            try:
                self.writer.close()
            except Exception:
                pass
        self.reader = self.writer = None

    async def _connect(self):
        """Подключается ко всем DoT-серверам одновременно и берёт первый
        ответивший: недоступный сервер не тормозит запуск."""
        async def one(idx):
            host, sni = UPSTREAMS[idx]
            r, w = await asyncio.wait_for(
                asyncio.open_connection(host, 853, ssl=self.ctx, server_hostname=sni), CONNECT_TIMEOUT
            )
            return idx, r, w

        # сначала тот сервер, что работал в прошлый раз
        order = [(self.upstream + i) % len(UPSTREAMS) for i in range(len(UPSTREAMS))]
        tasks = [asyncio.ensure_future(one(i)) for i in order]
        last = None
        try:
            for fut in asyncio.as_completed(tasks):
                try:
                    self.upstream, self.reader, self.writer = await fut
                    return
                except Exception as e:
                    last = e
        finally:
            for t in tasks:
                if not t.done():
                    t.cancel()
                elif not t.cancelled() and t.exception() is None and t.result()[2] is not self.writer:
                    t.result()[2].close()  # лишние успешные соединения закрываем
        raise ConnectionError(f"DoT недоступен: {last}")

    async def query(self, data: bytes) -> bytes:
        async with self.lock:
            for attempt in range(2):
                try:
                    if self.writer is None:
                        await self._connect()
                    self.writer.write(struct.pack("!H", len(data)) + data)
                    await self.writer.drain()
                    (n,) = struct.unpack("!H", await asyncio.wait_for(self.reader.readexactly(2), TIMEOUT))
                    return await asyncio.wait_for(self.reader.readexactly(n), TIMEOUT)
                except Exception:
                    # сервер закрыл keep-alive соединение — переподключаемся один раз
                    self._close()
                    if attempt:
                        raise
        raise ConnectionError("unreachable")


def _servfail(query: bytes) -> bytes:
    if len(query) < 12:
        return b""
    flags = struct.unpack("!H", query[2:4])[0]
    resp_flags = 0x8000 | (flags & 0x7900) | 0x0080 | 0x0002  # QR, opcode, RD, RA, SERVFAIL
    return query[:2] + struct.pack("!H", resp_flags) + query[4:6] + b"\x00" * 6 + query[12:]


def _truncate_for_udp(query: bytes, resp: bytes) -> bytes:
    """Ответы больше 512 байт без EDNS отдаём с флагом TC — клиент повторит по TCP."""
    has_edns = len(query) >= 12 and struct.unpack("!H", query[10:12])[0] > 0
    if len(resp) <= 512 or (has_edns and len(resp) <= 1232):
        return resp
    return resp[:2] + bytes([resp[2] | 0x02, resp[3]]) + b"\x00" * 8


class DnsProxy:
    def __init__(self, log):
        self.log = log
        ctx = _ssl_context()
        self.pool = [_DotConn(ctx) for _ in range(POOL_SIZE)]
        self.rr = 0
        self.udp = None
        self.tcp = None

    async def query(self, data: bytes) -> bytes:
        free = [c for c in self.pool if not c.lock.locked()]
        if free:
            conn = free[0]
        else:
            conn = self.pool[self.rr % len(self.pool)]
            self.rr += 1
        try:
            return await conn.query(data)
        except Exception as e:
            self.log.warning(f"DoT: {e}")
            return _servfail(data)

    async def start(self):
        loop = asyncio.get_running_loop()
        proxy = self

        class Udp(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                self.transport = transport

            def datagram_received(self, data, addr):
                asyncio.ensure_future(self._handle(data, addr))

            async def _handle(self, data, addr):
                resp = await proxy.query(data)
                if resp:
                    self.transport.sendto(_truncate_for_udp(data, resp), addr)

        async def tcp_client(reader, writer):
            try:
                while True:
                    (n,) = struct.unpack("!H", await asyncio.wait_for(reader.readexactly(2), 30))
                    data = await reader.readexactly(n)
                    resp = await proxy.query(data)
                    writer.write(struct.pack("!H", len(resp)) + resp)
                    await writer.drain()
            except Exception:
                pass
            finally:
                writer.close()

        self.udp, _ = await loop.create_datagram_endpoint(Udp, local_addr=(LISTEN_ADDR, LISTEN_PORT))
        self.tcp = await asyncio.start_server(tcp_client, LISTEN_ADDR, LISTEN_PORT)
        # прогреваем соединение, чтобы сразу увидеть, если DoT недоступен
        await self.pool[0]._connect()
        self.log.info(f"DNS-over-TLS прокси слушает {LISTEN_ADDR}:{LISTEN_PORT}")

    async def stop(self):
        if self.udp:
            self.udp.close()
            self.udp = None
        if self.tcp:
            self.tcp.close()
            await self.tcp.wait_closed()
            self.tcp = None
        for c in self.pool:
            c._close()
