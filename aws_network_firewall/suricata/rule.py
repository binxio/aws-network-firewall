from __future__ import annotations

from dataclasses import dataclass
from typing import List

from aws_network_firewall.suricata.host import Host
from aws_network_firewall.suricata.option import Option


@dataclass
class Rule:
    """
    Understands to export a suricata rule
    """

    action: str
    protocol: str
    sources: List[Host]
    destination: Host
    options: List[Option]

    def __post_init__(self):
        self.protocol = self.protocol.lower()

    @property
    def source(self) -> str:
        addresses = list(map(lambda host: host.address, self.sources))
        sources = ",".join(addresses)
        return f"[{sources}] any" if len(addresses) > 1 else f"{sources} any"

    def __str__(self) -> str:
        options = "; ".join(list(map(str, self.options)))
        return f"{self.action} {self.protocol} {self.source} -> {self.destination} ({options})"
