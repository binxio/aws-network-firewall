from aws_network_firewall.cidr_ranges import CidrRanges
from aws_network_firewall.source import Source


def test_source_region_to_cidr(cidr_ranges: CidrRanges) -> None:
    source = Source(
        description="",
        region="eu-west-1",
        cidr=None,
    )
    source.resolve_region_cidr_ranges(cidr_ranges)
    assert source.cidr == "10.0.0.0/24"


def test_source_cidr(cidr_ranges: CidrRanges) -> None:
    source = Source(
        description="",
        region=None,
        cidr="10.0.0.0/24",
    )
    source.resolve_region_cidr_ranges(cidr_ranges)
    assert source.cidr == "10.0.0.0/24"
