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
    def direction(self) -> str:
        return "<>" if self.protocol == "icmp" else "->"

    @property
    def source(self) -> str:
        addresses = list(map(lambda host: host.address, self.sources))
        sources = ",".join(addresses)
        return f"[{sources}] any" if len(addresses) > 1 else f"{sources} any"

    def __str__(self) -> str:
        post_rule = ""
        options = "; ".join(list(map(str, self.options)))

        if self.protocol == "tls" and self.destination.port != 443:
            message = next(
                filter(lambda option: option.name == "msg", self.options),
                Option(name="msg", value="Unknown"),
            )
            message.value = (
                f"{message.value} | Pass non-established TCP for 3-way handshake"
            )
            flow = Option(name="flow", value="not_established")  # No quotes
            sid = Option(name="sid", value="XXX", quoted_value=False)
            rev = Option(name="rev", value="1", quoted_value=False)

            handshake_options = "; ".join(list(map(str, [message, flow, rev, sid])))

            post_rule = f"\n{self.action} tcp {self.source} <> {self.destination} ({handshake_options};)"

        return f"{self.action} {self.protocol} {self.source} {self.direction} {self.destination} ({options};){post_rule}"
