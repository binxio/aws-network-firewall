from aws_network_firewall.destination import Destination
from aws_network_firewall.rule import Rule
from aws_network_firewall.source import Source


def test_rule_with_tls_endpoint() -> None:
    rule = Rule(
        workload="my-workload",
        name="my-rule",
        region="eu-west-1",
        type=Rule.INSPECTION,
        description="My description",
        sources=[Source(description="my source", cidr="10.0.0.0/24")],
        destinations=[
            Destination(
                description="my destination",
                protocol="TLS",
                port=443,
                endpoint="xebia.com",
                cidr="10.0.1.0/24",
                message=None,
                tls_versions=[],
            )
        ],
    )

    assert (
        'pass tls 10.0.0.0/24 any -> 10.0.1.0/24 443 (tls.sni; content:"xebia.com"; nocase; startswith; endswith; msg:"my-workload | my-rule"; rev:1; sid:XXX;)'
        == str(rule)
    )


def test_rule_with_tls_1_2_endpoint() -> None:
    rule = Rule(
        workload="my-workload",
        name="my-rule",
        region="eu-west-1",
        type=Rule.INSPECTION,
        description="My description",
        sources=[Source(description="my source", cidr="10.0.0.0/24")],
        destinations=[
            Destination(
                description="my destination",
                protocol="TLS",
                port=443,
                endpoint="xebia.com",
                cidr="10.0.1.0/24",
                message=None,
                tls_versions=["tls1.2"],
            )
        ],
    )

    assert (
        'pass tls 10.0.0.0/24 any -> 10.0.1.0/24 443 (tls.sni; ssl_version:tls1.2; content:"xebia.com"; nocase; startswith; endswith; msg:"my-workload | my-rule"; rev:1; sid:XXX;)'
        == str(rule)
    )


def test_rule_with_tls_1_3_endpoint() -> None:
    rule = Rule(
        workload="my-workload",
        name="my-rule",
        region="eu-west-1",
        type=Rule.INSPECTION,
        description="My description",
        sources=[Source(description="my source", cidr="10.0.0.0/24")],
        destinations=[
            Destination(
                description="my destination",
                protocol="TLS",
                port=443,
                endpoint="xebia.com",
                cidr="10.0.1.0/24",
                message=None,
                tls_versions=["tls1.3"],
            )
        ],
    )

    assert (
        'pass tls 10.0.0.0/24 any -> 10.0.1.0/24 443 (tls.sni; ssl_version:tls1.3; content:"xebia.com"; nocase; startswith; endswith; msg:"my-workload | my-rule"; rev:1; sid:XXX;)'
        == str(rule)
    )


def test_rule_with_tls_1_2_and_1_3_endpoint() -> None:
    rule = Rule(
        workload="my-workload",
        name="my-rule",
        region="eu-west-1",
        type=Rule.INSPECTION,
        description="My description",
        sources=[Source(description="my source", cidr="10.0.0.0/24")],
        destinations=[
            Destination(
                description="my destination",
                protocol="TLS",
                port=443,
                endpoint="xebia.com",
                cidr="10.0.1.0/24",
                message=None,
                tls_versions=["tls1.2", "tls1.3"],
            )
        ],
    )

    assert (
        'pass tls 10.0.0.0/24 any -> 10.0.1.0/24 443 (tls.sni; ssl_version:tls1.2,tls1.3; content:"xebia.com"; nocase; startswith; endswith; msg:"my-workload | my-rule"; rev:1; sid:XXX;)'
        == str(rule)
    )


def test_rule_with_tls_wildcard_endpoint() -> None:
    rule = Rule(
        workload="my-workload",
        name="my-rule",
        region="eu-west-1",
        type=Rule.INSPECTION,
        description="My description",
        sources=[Source(description="my source", cidr="10.0.0.0/24")],
        destinations=[
            Destination(
                description="my destination",
                protocol="TLS",
                port=443,
                endpoint="*.xebia.com",
                cidr="10.0.1.0/24",
                message=None,
                tls_versions=[],
            )
        ],
    )

    assert (
        'pass tls 10.0.0.0/24 any -> 10.0.1.0/24 443 (tls.sni; dotprefix; content:".xebia.com"; nocase; endswith; msg:"my-workload | my-rule"; rev:1; sid:XXX;)'
        == str(rule)
    )


def test_rule_with_tls_endpoint_non_standard_port() -> None:
    rule = Rule(
        workload="my-workload",
        name="my-rule",
        region="eu-west-1",
        type=Rule.INSPECTION,
        description="My description",
        sources=[Source(description="my source", cidr="10.0.0.0/24")],
        destinations=[
            Destination(
                description="my destination",
                protocol="TLS",
                port=444,
                endpoint="xebia.com",
                cidr="10.0.1.0/24",
                message=None,
                tls_versions=[],
            )
        ],
    )

    assert (
        'pass tls 10.0.0.0/24 any -> 10.0.1.0/24 444 (tls.sni; content:"xebia.com"; nocase; startswith; endswith; msg:"my-workload | my-rule"; rev:1; sid:XXX;)\n'
        + 'pass tcp 10.0.0.0/24 any <> 10.0.1.0/24 444 (flow:"not_established"; msg:"Pass non-established TCP for 3-way handshake | my-workload | my-rule"; rev:1; sid:XXX;)'
        == str(rule)
    )


def test_rule_with_tls_endpoint_non_standard_port_and_message() -> None:
    rule = Rule(
        workload="my-workload",
        name="my-rule",
        region="eu-west-1",
        type=Rule.INSPECTION,
        description="My description",
        sources=[Source(description="my source", cidr="10.0.0.0/24")],
        destinations=[
            Destination(
                description="my destination",
                protocol="TLS",
                port=444,
                endpoint="xebia.com",
                cidr="10.0.1.0/24",
                message="IMPORTANT",
                tls_versions=[],
            )
        ],
    )

    assert (
        'pass tls 10.0.0.0/24 any -> 10.0.1.0/24 444 (tls.sni; content:"xebia.com"; nocase; startswith; endswith; msg:"IMPORTANT | my-workload | my-rule"; rev:1; sid:XXX;)\n'
        + 'pass tcp 10.0.0.0/24 any <> 10.0.1.0/24 444 (flow:"not_established"; msg:"IMPORTANT | Pass non-established TCP for 3-way handshake | my-workload | my-rule"; rev:1; sid:XXX;)'
        == str(rule)
    )


def test_rule_with_tcp_cidr() -> None:
    rule = Rule(
        workload="my-workload",
        name="my-rule",
        region="eu-west-1",
        type=Rule.INSPECTION,
        description="My description",
        sources=[Source(description="my source", cidr="10.0.0.0/24")],
        destinations=[
            Destination(
                description="my destination",
                protocol="TCP",
                port=443,
                cidr="10.0.1.0/24",
                endpoint=None,
                message=None,
                tls_versions=[],
            )
        ],
    )

    assert (
        'pass tcp 10.0.0.0/24 any -> 10.0.1.0/24 443 (msg:"my-workload | my-rule"; rev:1; sid:XXX;)'
        == str(rule)
    )


def test_icmp_rule() -> None:
    rule = Rule(
        workload="my-workload",
        name="my-rule",
        region="eu-west-1",
        type=Rule.INSPECTION,
        description="My description",
        sources=[Source(description="my source", cidr="10.0.0.0/24")],
        destinations=[
            Destination(
                description="my destination",
                protocol="ICMP",
                port=None,
                cidr="10.0.1.0/24",
                endpoint=None,
                message=None,
                tls_versions=[],
            )
        ],
    )

    assert (
        'pass icmp 10.0.0.0/24 any <> 10.0.1.0/24 any (msg:"my-workload | my-rule"; rev:1; sid:XXX;)'
        == str(rule)
    )


def test_egress_tls_rule() -> None:
    rule = Rule(
        workload="my-workload",
        name="my-rule",
        region="eu-west-1",
        type=Rule.EGRESS,
        description="My description",
        sources=[Source(description="my source", cidr=None)],
        destinations=[
            Destination(
                description="my destination",
                protocol="TLS",
                port=443,
                cidr=None,
                endpoint="xebia.com",
                message=None,
                tls_versions=[],
            )
        ],
    )

    assert (
        'pass tls  any -> any 443 (tls.sni; content:"xebia.com"; nocase; startswith; endswith; msg:"my-workload | my-rule"; rev:1; sid:XXX;)'
        == str(rule)
    )


def test_egress_tls_rule_with_message() -> None:
    rule = Rule(
        workload="my-workload",
        name="my-rule",
        region="eu-west-1",
        type=Rule.EGRESS,
        description="My description",
        sources=[Source(description="my source", cidr=None)],
        destinations=[
            Destination(
                description="my destination",
                protocol="TLS",
                port=443,
                cidr=None,
                endpoint="xebia.com",
                message="IMPORTANT BECAUSE ...",
                tls_versions=[],
            )
        ],
    )

    assert (
        'pass tls  any -> any 443 (tls.sni; content:"xebia.com"; nocase; startswith; endswith; msg:"IMPORTANT BECAUSE ... | my-workload | my-rule"; rev:1; sid:XXX;)'
        == str(rule)
    )
