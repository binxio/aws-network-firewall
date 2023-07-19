from aws_network_firewall.destination import Destination
from aws_network_firewall.rule import Rule
from aws_network_firewall.source import Source


def test_rule_with_tls_endpoint() -> None:
    rule = Rule(
        workload="my-workload",
        name="my-rule",
        description="My description",
        sources=[Source(description="my source", cidr="10.0.0.0/24", region=None)],
        destinations=[
            Destination(
                description="my destination",
                protocol="TLS",
                port=443,
                endpoint="xebia.com",
                cidr="10.0.1.0/24",
                region=None,
            )
        ],
    )

    assert (
        'pass tls 10.0.0.0/24 any -> 10.0.1.0/24 443 (tls.sni; content:"xebia.com"; nocase; startswith; endswith; msg:"my-workload | my-rule"; rev:"1"; sid:"XXX")'
        == str(rule)
    )


def test_rule_with_tls_wildcard_endpoint() -> None:
    rule = Rule(
        workload="my-workload",
        name="my-rule",
        description="My description",
        sources=[Source(description="my source", cidr="10.0.0.0/24", region=None)],
        destinations=[
            Destination(
                description="my destination",
                protocol="TLS",
                port=443,
                endpoint="*.xebia.com",
                cidr="10.0.1.0/24",
                region=None,
            )
        ],
    )

    assert (
        'pass tls 10.0.0.0/24 any -> 10.0.1.0/24 443 (tls.sni; dotprefix; content:".xebia.com"; nocase; endswith; msg:"my-workload | my-rule"; rev:"1"; sid:"XXX")'
        == str(rule)
    )


def test_rule_with_tcp_cidr() -> None:
    rule = Rule(
        workload="my-workload",
        name="my-rule",
        description="My description",
        sources=[Source(description="my source", cidr="10.0.0.0/24", region=None)],
        destinations=[
            Destination(
                description="my destination",
                protocol="TCP",
                port=443,
                cidr="10.0.1.0/24",
                endpoint=None,
                region=None,
            )
        ],
    )

    assert (
        'pass tcp 10.0.0.0/24 any -> 10.0.1.0/24 443 (msg:"my-workload | my-rule"; rev:"1"; sid:"XXX")'
        == str(rule)
    )


def test_rule_no_cidr() -> None:
    rule = Rule(
        workload="my-workload",
        name="my-rule",
        description="My description",
        sources=[Source(description="my source", cidr="10.0.0.0/24", region=None)],
        destinations=[
            Destination(
                description="my destination",
                protocol="TCP",
                port=443,
                cidr=None,
                endpoint=None,
                region=None,
            )
        ],
    )

    assert "" == str(rule)
