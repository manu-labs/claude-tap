"""CLI entry point for claude-tap (agentteam headless mode).

Supports two modes:
  1. Headless forward proxy with per-host routing (for sandbox use)
  2. CA certificate generation (for image build)

Usage:
  claude-tap --headless --port 9222 \
      --route api.anthropic.com=http://gateway:8001/internal/proxy/anthropic \
      --route api.openai.com=http://gateway:8001/internal/proxy/openai

  claude-tap --generate-ca
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys

import aiohttp

from claude_tap.certs import CertificateAuthority, ensure_ca
from claude_tap.forward_proxy import ForwardProxyServer

log = logging.getLogger("claude-tap")

try:
    from importlib.metadata import version as _pkg_version
    __version__ = _pkg_version("claude-tap")
except Exception:
    __version__ = "0.0.0"


def _parse_route(route_str: str) -> tuple[str, str]:
    """Parse 'hostname=url' into (hostname, url)."""
    if "=" not in route_str:
        raise argparse.ArgumentTypeError(f"Invalid route format: {route_str!r} (expected host=url)")
    host, url = route_str.split("=", 1)
    return host.strip(), url.strip()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        prog="claude-tap",
        description="Forward proxy with CONNECT/TLS termination and per-host routing.",
    )
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")

    parser.add_argument(
        "--generate-ca", action="store_true",
        help="Generate CA certificate and exit (for image build)",
    )
    parser.add_argument(
        "--headless", action="store_true",
        help="Headless mode: no traces, no viewer, minimal output",
    )
    parser.add_argument(
        "--port", type=int, default=0,
        help="Proxy port (default: auto-assign)",
    )
    parser.add_argument(
        "--host", default="127.0.0.1",
        help="Bind address (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--route", action="append", default=[],
        help="Route rule: hostname=backend_url (repeatable)",
    )

    return parser.parse_args(argv)


async def _run_proxy(args: argparse.Namespace) -> int:
    """Run the forward proxy server."""
    # Parse routes
    routes: dict[str, str] = {}
    for route_str in args.route:
        host, url = _parse_route(route_str)
        routes[host] = url

    if not routes:
        print("WARNING: No routes configured — all CONNECT requests will be rejected", file=sys.stderr)

    # Ensure CA exists
    ca_cert_path, ca_key_path = ensure_ca()
    ca = CertificateAuthority(ca_cert_path, ca_key_path)

    # Logging to stderr only
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s %(message)s", datefmt="%H:%M:%S"))
    log.addHandler(handler)
    log.setLevel(logging.INFO)

    session = aiohttp.ClientSession(auto_decompress=False, trust_env=True)

    server = ForwardProxyServer(
        host=args.host,
        port=args.port,
        ca=ca,
        session=session,
        routes=routes,
    )

    actual_port = await server.start()

    # Ready signal — read by the parent process to know the proxy is accepting
    print(f"READY {actual_port}", flush=True)

    if not args.headless:
        print(f"claude-tap v{__version__} forward proxy on http://{args.host}:{actual_port}", file=sys.stderr)
        print(f"CA cert: {ca_cert_path}", file=sys.stderr)
        for host, url in routes.items():
            print(f"  {host} -> {url}", file=sys.stderr)

    # Wait for shutdown signal
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except (NotImplementedError, OSError):
            pass

    await stop.wait()

    await server.stop()
    await session.close()
    return 0


def main_entry() -> None:
    """Entry point for the claude-tap CLI."""
    args = parse_args()

    if args.generate_ca:
        ca_cert_path, _ = ensure_ca()
        print(f"CA certificate: {ca_cert_path}")
        sys.exit(0)

    try:
        code = asyncio.run(_run_proxy(args))
    except KeyboardInterrupt:
        code = 0
    sys.exit(code)
