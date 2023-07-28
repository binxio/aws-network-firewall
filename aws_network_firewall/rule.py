from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, ClassVar

from aws_network_firewall.source import Source
from aws_network_firewall.destination import Destination
from aws_network_firewall.suricata import SuricataRule, SuricataHost, SuricataOption


@dataclass
class Rule:
    """
    Understands a rule
    """

    workload: str
    name: str
    type: str
    description: str
    sources: List[Source]
    destinations: List[Destination]

    INSPECTION: ClassVar[str] = "Inspection"
    EGRESS: ClassVar[str] = "Egress"

    @property
    def is_inspection_rule(self) -> bool:
        return self.type == self.INSPECTION

    @property
    def is_egress_rule(self) -> bool:
        return self.type == self.EGRESS

    @property
    def __suricata_source(self) -> List[SuricataHost]:
        def convert_source(source: Source) -> Optional[SuricataHost]:
            return SuricataHost(address=source.cidr, port=0) if source.cidr else None

        return list(filter(None, map(convert_source, self.sources)))

    @staticmethod
    def __tls_endpoint_options(endpoint: str) -> List[SuricataOption]:
        options = [
            SuricataOption(name="tls.sni"),
            SuricataOption(name="tls.version", value="1.2", quoted_value=False),
            # When using multiple tls versions you need 2 rules
            # openssl 1.1.1 is needed for tls1.3
            # SuricataOption(name="tls.version", value="1.3", quoted_value=False),
        ]

        if endpoint.startswith("*"):
            options += [
                SuricataOption(name="dotprefix"),
                SuricataOption(name="content", value=endpoint[1:]),
                SuricataOption(name="nocase"),
                SuricataOption(name="endswith"),
            ]
        else:
            options += [
                SuricataOption(name="content", value=endpoint),
                SuricataOption(name="nocase"),
                SuricataOption(name="startswith"),
                SuricataOption(name="endswith"),
            ]

        return options

    def __resolve_options(self, destination: Destination) -> List[SuricataOption]:
        options = []

        if destination.protocol == "TLS" and destination.endpoint:
            options = self.__tls_endpoint_options(destination.endpoint)

        message = (
            f"{destination.message} | {self.workload} | {self.name}"
            if destination.message
            else f"{self.workload} | {self.name}"
        )

        return options + [
            SuricataOption(name="msg", value=message),
            SuricataOption(name="rev", value="1", quoted_value=False),
            SuricataOption(name="sid", value="XXX", quoted_value=False),
        ]

    def __resolve_rule(self, destination: Destination) -> SuricataRule:
        return SuricataRule(
            action="pass",
            protocol=destination.protocol,
            sources=self.__suricata_source,
            destination=SuricataHost(
                address=destination.cidr if destination.cidr else "",
                port=destination.port if destination.port else 0,
            ),
            options=self.__resolve_options(destination),
        )

    @property
    def suricata_rules(self) -> List[SuricataRule]:
        rules = list(filter(None, map(self.__resolve_rule, self.destinations)))
        return rules

    def __str__(self) -> str:
        return "\n".join(map(str, self.suricata_rules))
