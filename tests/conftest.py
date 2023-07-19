import pytest

from aws_network_firewall.cidr_ranges import CidrRanges
from aws_network_firewall.cidr_range import CidrRange


@pytest.fixture
def cidr_ranges() -> CidrRanges:
    return CidrRanges(cidr_ranges=[CidrRange(region="eu-west-1", value="10.0.0.0/24")])
