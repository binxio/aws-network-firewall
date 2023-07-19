from aws_network_firewall.cidr_ranges import CidrRanges
from aws_network_firewall.destination import Destination


def test_destination_region_to_cidr(cidr_ranges: CidrRanges) -> None:
    destination = Destination(
        description="",
        protocol="TLS",
        port=443,
        region="eu-west-1",
        endpoint=None,
        cidr=None,
    )
    destination.resolve_region_cidr_ranges(cidr_ranges)
    assert destination.cidr == "10.0.0.0/24"


def test_destination_cidr(cidr_ranges: CidrRanges) -> None:
    destination = Destination(
        description="",
        protocol="TLS",
        port=443,
        region=None,
        endpoint=None,
        cidr="10.0.0.0/24",
    )
    destination.resolve_region_cidr_ranges(cidr_ranges)
    assert destination.cidr == "10.0.0.0/24"
