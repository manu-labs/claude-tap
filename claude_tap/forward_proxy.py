"""Forward proxy server with CONNECT/TLS termination and multi-target routing.

Implements an HTTP forward proxy that handles CONNECT tunneling with
man-in-the-middle TLS termination. Routes requests to different backends
based on the CONNECT hostname.

Flow:
  1. Client sends CONNECT api.anthropic.com:443
  2. Proxy looks up route for api.anthropic.com → gateway URL
  3. Proxy responds 200 Connection Established
  4. Client starts TLS handshake; proxy presents a cert signed by our CA
  5. Client sends plaintext HTTP request inside the TLS tunnel
  6. Proxy forwards to the gateway backend, pipes response back
"""

from __future__ import annotations

import asyncio
import json
import logging
import time

import aiohttp

from claude_tap.certs import CertificateAuthority

log = logging.getLogger("claude-tap")

# Hop-by-hop headers that should not be forwarded
HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
})


def _filter_headers(headers: dict[str, str]) -> dict[str, str]:
    """Remove hop-by-hop headers."""
    return {k: v for k, v in headers.items() if k.lower() not in HOP_BY_HOP}


class ForwardProxyServer:
    """Async TCP server that acts as an HTTP forward proxy with CONNECT support.

    Routes requests to different backends based on the CONNECT hostname.
    If no routes are configured, forwards to the original upstream (passthrough).
    """

    def __init__(
        self,
        host: str,
        port: int,
        ca: CertificateAuthority,
        session: aiohttp.ClientSession,
        routes: dict[str, str] | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self._ca = ca
        self._session = session
        self._routes = routes or {}
        self._server: asyncio.Server | None = None
        self._turn_counter = 0
        self.actual_port: int = port

    async def start(self) -> int:
        """Start the forward proxy server. Returns the actual port."""
        self._server = await asyncio.start_server(self._handle_client, self.host, self.port)
        sock = self._server.sockets[0]
        self.actual_port = sock.getsockname()[1]
        return self.actual_port

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Handle an incoming client connection."""
        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=30)
            if not request_line:
                writer.close()
                return

            request_str = request_line.decode("utf-8", errors="replace").strip()
            parts = request_str.split(" ")
            if len(parts) < 3:
                writer.close()
                return

            method = parts[0].upper()

            if method == "CONNECT":
                await self._handle_connect(parts[1], reader, writer)
            else:
                # Non-CONNECT — reject in routed mode
                error_body = b"Only CONNECT is supported"
                writer.write(b"HTTP/1.1 405 Method Not Allowed\r\n")
                writer.write(f"Content-Length: {len(error_body)}\r\n\r\n".encode())
                writer.write(error_body)
                await writer.drain()
        except (ConnectionError, asyncio.TimeoutError, asyncio.CancelledError):
            pass
        except Exception:
            log.exception("Error handling forward proxy connection")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _handle_connect(
        self,
        authority: str,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle CONNECT method: TLS termination + request interception."""
        if ":" in authority:
            hostname, port_str = authority.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                port = 443
        else:
            hostname = authority
            port = 443

        # Look up route for this hostname
        route_url = self._routes.get(hostname)
        if self._routes and route_url is None:
            # Host not in route table — reject
            log.warning("CONNECT to unrouted host %s — rejecting", hostname)
            # Read remaining headers
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=10)
                if line in (b"\r\n", b"\n", b""):
                    break
            writer.write(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            await writer.drain()
            return

        # Read and discard remaining headers until blank line
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=10)
            if line in (b"\r\n", b"\n", b""):
                break

        # Send 200 Connection Established
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()

        # TLS termination via a local loopback bounce
        ssl_ctx = self._ca.make_ssl_context(hostname)

        tls_reader_holder: list[asyncio.StreamReader] = []
        tls_writer_holder: list[asyncio.StreamWriter] = []
        connected = asyncio.Event()

        async def _accept_tls(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
            tls_reader_holder.append(r)
            tls_writer_holder.append(w)
            connected.set()

        tls_server = await asyncio.start_server(_accept_tls, "127.0.0.1", 0, ssl=ssl_ctx)
        tls_port = tls_server.sockets[0].getsockname()[1]

        raw_sock = writer.transport.get_extra_info("socket")
        if raw_sock is None:
            tls_server.close()
            log.warning("Cannot get raw socket for %s", hostname)
            return

        try:
            relay_r, relay_w = await asyncio.open_connection("127.0.0.1", tls_port)
        except (ConnectionError, OSError) as e:
            tls_server.close()
            log.warning("Cannot connect to TLS relay for %s: %s", hostname, e)
            return

        async def _pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
            try:
                while True:
                    data = await src.read(65536)
                    if not data:
                        break
                    dst.write(data)
                    await dst.drain()
            except (ConnectionError, asyncio.CancelledError):
                pass
            finally:
                try:
                    dst.close()
                except Exception:
                    pass

        relay_task = asyncio.create_task(_pipe(relay_r, writer))
        client_to_relay_task = asyncio.create_task(_pipe(reader, relay_w))

        try:
            await asyncio.wait_for(connected.wait(), timeout=15)
        except asyncio.TimeoutError:
            log.warning("TLS handshake timed out for %s", hostname)
            relay_task.cancel()
            client_to_relay_task.cancel()
            tls_server.close()
            return

        tls_server.close()
        tls_reader = tls_reader_holder[0]
        tls_writer = tls_writer_holder[0]

        try:
            await self._handle_tunneled_requests(
                hostname, port, route_url, tls_reader, tls_writer,
            )
        finally:
            relay_task.cancel()
            client_to_relay_task.cancel()
            try:
                tls_writer.close()
                await tls_writer.wait_closed()
            except Exception:
                pass

    async def _handle_tunneled_requests(
        self,
        hostname: str,
        port: int,
        route_url: str | None,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Read HTTP requests from inside the TLS tunnel and proxy them."""
        while True:
            try:
                request_line = await asyncio.wait_for(reader.readline(), timeout=600)
            except (asyncio.TimeoutError, ConnectionError):
                break
            if not request_line:
                break

            request_str = request_line.decode("utf-8", errors="replace").strip()
            if not request_str:
                break

            parts = request_str.split(" ", 2)
            if len(parts) < 3:
                break

            method, path, _http_version = parts

            # Read headers
            headers: dict[str, str] = {}
            while True:
                header_line = await asyncio.wait_for(reader.readline(), timeout=30)
                if header_line in (b"\r\n", b"\n", b""):
                    break
                decoded = header_line.decode("utf-8", errors="replace").strip()
                if ":" in decoded:
                    key, value = decoded.split(":", 1)
                    headers[key.strip()] = value.strip()

            # Read body if Content-Length is present
            body = b""
            content_length = headers.get("Content-Length") or headers.get("content-length")
            if content_length:
                try:
                    length = int(content_length)
                    body = await asyncio.wait_for(reader.readexactly(length), timeout=60)
                except (ValueError, asyncio.IncompleteReadError, asyncio.TimeoutError):
                    pass

            # Build upstream URL
            if route_url:
                upstream_url = f"{route_url.rstrip('/')}{path}"
            else:
                upstream_url = f"https://{hostname}:{port}{path}"

            await self._forward(method, path, headers, body, upstream_url, writer)

    async def _forward(
        self,
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes,
        upstream_url: str,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        """Forward request to upstream and pipe response back."""
        self._turn_counter += 1
        turn = self._turn_counter
        t0 = time.monotonic()
        log_prefix = f"[Turn {turn}]"

        # Detect streaming for response handling
        is_streaming = False
        try:
            req_body = json.loads(body) if body else None
            if isinstance(req_body, dict):
                is_streaming = req_body.get("stream", False)
        except (json.JSONDecodeError, ValueError):
            pass

        log.info("%s -> %s %s (stream=%s)", log_prefix, method, upstream_url[:120], is_streaming)

        # Prepare forwarding headers — keep all original headers (including auth)
        fwd_headers = _filter_headers(headers)
        fwd_headers.pop("Host", None)
        fwd_headers.pop("host", None)
        fwd_headers["Accept-Encoding"] = "identity"

        try:
            upstream_resp = await self._session.request(
                method=method,
                url=upstream_url,
                headers=fwd_headers,
                data=body,
                timeout=aiohttp.ClientTimeout(total=600, sock_read=300),
            )
        except Exception as exc:
            log.error("%s upstream error: %s", log_prefix, exc)
            error_body = str(exc).encode()
            client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\n")
            client_writer.write(f"Content-Length: {len(error_body)}\r\nContent-Type: text/plain\r\n\r\n".encode())
            client_writer.write(error_body)
            await client_writer.drain()
            return

        if is_streaming and upstream_resp.status == 200:
            await self._handle_streaming(upstream_resp, client_writer, log_prefix, t0)
        else:
            await self._handle_non_streaming(upstream_resp, client_writer, log_prefix, t0)

    async def _handle_streaming(
        self,
        upstream_resp: aiohttp.ClientResponse,
        client_writer: asyncio.StreamWriter,
        log_prefix: str,
        t0: float,
    ) -> None:
        """Pipe a streaming response back through the TLS tunnel."""
        status_line = f"HTTP/1.1 {upstream_resp.status} {upstream_resp.reason}\r\n"
        client_writer.write(status_line.encode())

        for key, value in upstream_resp.headers.items():
            if key.lower() not in HOP_BY_HOP:
                client_writer.write(f"{key}: {value}\r\n".encode())
        client_writer.write(b"Transfer-Encoding: chunked\r\n")
        client_writer.write(b"\r\n")
        await client_writer.drain()

        try:
            async for chunk in upstream_resp.content.iter_any():
                chunk_header = f"{len(chunk):x}\r\n".encode()
                client_writer.write(chunk_header + chunk + b"\r\n")
                await client_writer.drain()
        except (ConnectionError, asyncio.CancelledError):
            pass

        try:
            client_writer.write(b"0\r\n\r\n")
            await client_writer.drain()
        except (ConnectionError, Exception):
            pass

        duration_ms = int((time.monotonic() - t0) * 1000)
        log.info("%s <- 200 stream done (%dms)", log_prefix, duration_ms)

    async def _handle_non_streaming(
        self,
        upstream_resp: aiohttp.ClientResponse,
        client_writer: asyncio.StreamWriter,
        log_prefix: str,
        t0: float,
    ) -> None:
        """Pipe a non-streaming response back through the TLS tunnel."""
        resp_bytes = await upstream_resp.read()
        duration_ms = int((time.monotonic() - t0) * 1000)

        log.info("%s <- %d (%dms, %d bytes)", log_prefix, upstream_resp.status, duration_ms, len(resp_bytes))

        status_line = f"HTTP/1.1 {upstream_resp.status} {upstream_resp.reason}\r\n"
        client_writer.write(status_line.encode())
        skip_headers = HOP_BY_HOP | {"content-length"}
        for key, value in upstream_resp.headers.items():
            if key.lower() not in skip_headers:
                client_writer.write(f"{key}: {value}\r\n".encode())
        client_writer.write(f"Content-Length: {len(resp_bytes)}\r\n".encode())
        client_writer.write(b"\r\n")
        client_writer.write(resp_bytes)
        await client_writer.drain()
