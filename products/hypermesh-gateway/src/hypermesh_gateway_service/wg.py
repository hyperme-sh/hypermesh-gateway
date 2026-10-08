"""Apply the gateway side of a real WireGuard host peer.

One WireGuard peer per HOST, not per lease. Apply that peer once. A standing
wg-hm iface still receives the peer. Do not add or drop a peer on
lease_start or lease_stop. remove_peer is host teardown only (failed certification /
device revoke).

Panopticon assigns keys. This process holds the gateway private key and
calls `wg` / `ip` (CAP_NET_ADMIN, /dev/net/tun). Missing tun is a no-op
so unit tests and hosts without a kernel tun do not crash.
"""

from __future__ import annotations

import logging
import os
import subprocess
import tempfile
import time
from pathlib import Path

logger = logging.getLogger(__name__)

WG_IFACE = os.environ.get("HYPERMESH_WG_IFACE", "wg-hm")
WG_LISTEN_PORT = int(os.environ.get("HYPERMESH_WG_LISTEN_PORT", "51820"))
WG_GATEWAY_ADDR = os.environ.get("HYPERMESH_WG_GATEWAY_ADDR", "10.77.0.1/24")
PEER_HANDSHAKE_STALE_S = int(os.environ.get("HYPERMESH_WG_HANDSHAKE_STALE_S", "180"))
_applied_host_peers: set[str] = set()


def tun_available() -> bool:
    return Path("/dev/net/tun").exists()


def should_apply() -> bool:
    if os.environ.get("HYPERMESH_WG_APPLY", "1") in {"0", "false", "no"}:
        return False
    return tun_available()


def _run(cmd: list[str]) -> None:
    subprocess.run(cmd, check=True, capture_output=True, text=True)


def apply_gateway(
    *,
    server_private_key: str,
    peer_public_key: str,
    client_address: str,
    listen_port: int = WG_LISTEN_PORT,
) -> None:
    if not should_apply():
        logger.info("wireguard apply skipped (no tun or HYPERMESH_WG_APPLY=0)")
        return
    if not server_private_key or not peer_public_key:
        logger.info("wireguard apply skipped (missing keys)")
        return
    if peer_public_key in _applied_host_peers:
        logger.info("wireguard host peer already applied")
        return
    peer_ip = client_address.split("/", 1)[0]
    with tempfile.NamedTemporaryFile("w", delete=False) as handle:
        handle.write(server_private_key + "\n")
        key_path = handle.name
    try:
        os.chmod(key_path, 0o600)
        _ensure_iface(listen_port, key_path)
        _run(
            [
                "wg",
                "set",
                WG_IFACE,
                "peer",
                peer_public_key,
                "allowed-ips",
                peer_ip + "/32",
            ]
        )
        _ensure_address()
        _run(["ip", "link", "set", WG_IFACE, "up"])
        _applied_host_peers.add(peer_public_key)
        logger.info("wireguard gateway applied on %s", WG_IFACE)
    except FileNotFoundError:
        logger.warning("wireguard tools not installed; gateway apply skipped")
    except subprocess.CalledProcessError as exc:
        logger.warning("wireguard apply failed: %s", exc.returncode)
    finally:
        try:
            os.unlink(key_path)
        except OSError:
            pass


def _ensure_iface(listen_port: int, key_path: str) -> None:
    """Create wg-hm once. A standing iface must still accept `wg set`."""

    try:
        _run(["ip", "link", "add", WG_IFACE, "type", "wireguard"])
    except subprocess.CalledProcessError:
        logger.info("wireguard iface %s already present", WG_IFACE)
    _run(["wg", "set", WG_IFACE, "listen-port", str(listen_port), "private-key", key_path])


def _ensure_address() -> None:
    try:
        _run(["ip", "address", "add", WG_GATEWAY_ADDR, "dev", WG_IFACE])
    except subprocess.CalledProcessError:
        logger.info("wireguard address already present on %s", WG_IFACE)


def remove_peer(peer_public_key: str) -> None:
    """Host-level teardown only. Do not call on lease_start or lease_stop."""

    if not should_apply() or not peer_public_key:
        return
    try:
        _run(["wg", "set", WG_IFACE, "peer", peer_public_key, "remove"])
        _applied_host_peers.discard(peer_public_key)
    except (FileNotFoundError, subprocess.CalledProcessError):
        logger.info("wireguard peer remove skipped")


def peer_handshake_epoch(peer_public_key: str) -> int | None:
    """Last handshake unix time for a host peer. None if dump cannot be read.

    Does not add or drop a peer.
    """

    if not peer_public_key:
        return None
    try:
        result = subprocess.run(
            ["wg", "show", WG_IFACE, "dump"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 6 and parts[0] == peer_public_key:
            try:
                return int(parts[4])
            except ValueError:
                return None
    return 0


def peer_counters(peer_public_key: str) -> tuple[int, int, int]:
    """Return (rx_bytes, tx_bytes, handshake_present). Does not flap the peer."""

    if not peer_public_key:
        return (0, 0, 0)
    try:
        result = subprocess.run(
            ["wg", "show", WG_IFACE, "dump"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return (0, 0, 0)
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 8 and parts[0] == peer_public_key:
            try:
                handshake = int(parts[4])
                rx_bytes = int(parts[5])
                tx_bytes = int(parts[6])
            except ValueError:
                return (0, 0, 0)
            return (rx_bytes, tx_bytes, 1 if handshake > 0 else 0)
    return (0, 0, 0)


def peer_is_up(peer_public_key: str | None, *, now: int | None = None) -> bool:
    """Fail closed when the host peer is missing, never-handshaked, or stale.

    When WireGuard apply is off (unit tests / no tun), there is no kernel
    peer to read. Callers inject `app.state.peer_up` for those runs.
    """

    if not should_apply():
        return True
    if not peer_public_key:
        return False
    epoch = peer_handshake_epoch(peer_public_key)
    if epoch is None or epoch <= 0:
        return False
    clock = now if now is not None else int(time.time())
    return (clock - epoch) < PEER_HANDSHAKE_STALE_S

