from aws_network_firewall.destination import Destination


def test_destination_properties() -> None:
    destination = Destination(
        description="My Description",
        protocol="TLS",
        port=443,
        endpoint="xebia.com",
        cidr="10.0.0.0/24",
        message="Important Message",
    )
    assert destination.description == "My Description"
    assert destination.protocol == "TLS"
    assert destination.port == 443
    assert destination.endpoint == "xebia.com"
    assert destination.cidr == "10.0.0.0/24"
    assert destination.message == "Important Message"
