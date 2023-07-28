from aws_network_firewall.source import Source


def test_source_properties() -> None:
    source = Source(
        description="My Description",
        cidr="10.0.0.0/24",
    )
    assert source.description == "My Description"
    assert source.cidr == "10.0.0.0/24"
