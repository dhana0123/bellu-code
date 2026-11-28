"""Refuse outbound network connections from this process.

The service only talks over a Unix domain socket (or accepts on loopback).
After install() any connect to an IP socket raises, so a bug or a dependency
cannot open an outbound connection (Requirement 20.18).
"""
import socket

_installed = False
_orig = None


class OutboundNetworkBlocked(OSError):
    pass


def install() -> None:
    global _installed, _orig
    if _installed:
        return
    _installed = True
    orig_connect, orig_connect_ex = socket.socket.connect, socket.socket.connect_ex
    orig_sendto = socket.socket.sendto
    _orig = (orig_connect, orig_connect_ex, orig_sendto)

    def _blocked(sock) -> bool:
        return sock.family in (socket.AF_INET, socket.AF_INET6)

    def connect(self, address):
        if _blocked(self):
            raise OutboundNetworkBlocked("outbound network connections are disabled")
        return orig_connect(self, address)

    def connect_ex(self, address):
        if _blocked(self):
            raise OutboundNetworkBlocked("outbound network connections are disabled")
        return orig_connect_ex(self, address)

    def sendto(self, *args):
        if _blocked(self):
            raise OutboundNetworkBlocked("outbound network connections are disabled")
        return orig_sendto(self, *args)

    socket.socket.connect = connect
    socket.socket.connect_ex = connect_ex
    socket.socket.sendto = sendto


def uninstall() -> None:
    """Restore the original socket methods (for tests only)."""
    global _installed
    if _installed and _orig:
        socket.socket.connect, socket.socket.connect_ex, socket.socket.sendto = _orig
    _installed = False
