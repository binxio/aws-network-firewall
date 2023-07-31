from __future__ import annotations

import itertools
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
    region: str
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
    def __resolve_tls_options(
        destination: Destination, tls_version: Optional[str]
    ) -> List[SuricataOption]:
        options = [
            SuricataOption(name="tls.sni"),
        ]
        if tls_version:
            options.append(
                SuricataOption(
                    name="tls.version", value=tls_version, quoted_value=False
                )
            )

        if destination.endpoint.startswith("*"):  # type: ignore
            options += [
                SuricataOption(name="dotprefix"),
                SuricataOption(name="content", value=destination.endpoint[1:]),  # type: ignore
                SuricataOption(name="nocase"),
                SuricataOption(name="endswith"),
            ]
        else:
            options += [
                SuricataOption(name="content", value=destination.endpoint),
                SuricataOption(name="nocase"),
                SuricataOption(name="startswith"),
                SuricataOption(name="endswith"),
            ]

        return options

    def __resolve_options(self, destination: Destination) -> List[SuricataOption]:
        message = (
            f"{destination.message} | {self.workload} | {self.name}"
            if destination.message
            else f"{self.workload} | {self.name}"
        )

        return [
            SuricataOption(name="msg", value=message),
            SuricataOption(name="rev", value="1", quoted_value=False),
            SuricataOption(name="sid", value="XXX", quoted_value=False),
        ]

    def __resolve_tls_version_rules(
        self, destination: Destination
    ) -> List[SuricataRule]:
        rules = []

        for tls_version in destination.tls_versions:
            rules.append(
                SuricataRule(
                    action="pass",
                    protocol=destination.protocol,
                    sources=self.__suricata_source,
                    destination=SuricataHost(
                        address=destination.cidr if destination.cidr else "",
                        port=destination.port if destination.port else 0,
                    ),
                    options=self.__resolve_tls_options(
                        destination=destination, tls_version=tls_version
                    )
                    + self.__resolve_options(destination=destination),
                )
            )

        return rules

    def __resolve_tls_rules(self, destination: Destination) -> List[SuricataRule]:
        if destination.tls_versions:
            return self.__resolve_tls_version_rules(destination)

        return [
            SuricataRule(
                action="pass",
                protocol=destination.protocol,
                sources=self.__suricata_source,
                destination=SuricataHost(
                    address=destination.cidr if destination.cidr else "",
                    port=destination.port if destination.port else 0,
                ),
                options=self.__resolve_tls_options(
                    destination=destination, tls_version=None
                )
                + self.__resolve_options(destination=destination),
            )
        ]

    def __resolve_rule(self, destination: Destination) -> List[SuricataRule]:
        if destination.protocol == "TLS" and destination.endpoint:
            return self.__resolve_tls_rules(destination=destination)

        return [
            SuricataRule(
                action="pass",
                protocol=destination.protocol,
                sources=self.__suricata_source,
                destination=SuricataHost(
                    address=destination.cidr if destination.cidr else "",
                    port=destination.port if destination.port else 0,
                ),
                options=self.__resolve_options(destination),
            )
        ]

    @property
    def suricata_rules(self) -> List[SuricataRule]:
        rules = list(filter(None, map(self.__resolve_rule, self.destinations)))
        return list(itertools.chain.from_iterable(rules))

    def __str__(self) -> str:
        return "\n".join(map(str, self.suricata_rules))
