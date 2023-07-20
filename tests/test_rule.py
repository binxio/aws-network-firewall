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
        'pass tls 10.0.0.0/24 any -> 10.0.1.0/24 443 (tls.sni; tls.version:"1.2,1.3"; content:"xebia.com"; nocase; startswith; endswith; msg:"my-workload | my-rule"; rev:"1"; sid:"XXX")'
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
        'pass tls 10.0.0.0/24 any -> 10.0.1.0/24 443 (tls.sni; tls.version:"1.2,1.3"; dotprefix; content:".xebia.com"; nocase; endswith; msg:"my-workload | my-rule"; rev:"1"; sid:"XXX")'
        == str(rule)
    )


def test_rule_with_tls_endpoint_non_standard_port() -> None:
    rule = Rule(
        workload="my-workload",
        name="my-rule",
        description="My description",
        sources=[Source(description="my source", cidr="10.0.0.0/24", region=None)],
        destinations=[
            Destination(
                description="my destination",
                protocol="TLS",
                port=444,
                endpoint="xebia.com",
                cidr="10.0.1.0/24",
                region=None,
            )
        ],
    )

    assert (
        'pass tls 10.0.0.0/24 any -> 10.0.1.0/24 444 (tls.sni; tls.version:"1.2,1.3"; content:"xebia.com"; nocase; startswith; endswith; msg:"my-workload | my-rule"; rev:"1"; sid:"XXX")\n'
        + 'pass tcp 10.0.0.0/24 any <> 10.0.1.0/24 444 (msg:"my-workload | my-rule | Pass non-established TCP for 3-way handshake"; flow:"not_established"; rev:"1"; sid:"XXX")'
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
