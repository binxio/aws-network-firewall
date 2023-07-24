from aws_network_firewall.account import Account
from aws_network_firewall.cidr_range import CidrRange
from aws_network_firewall.cidr_ranges import CidrRanges
from aws_network_firewall.destination import Destination
from aws_network_firewall.rule import Rule
from aws_network_firewall.source import Source


def generate_rule(type: str) -> Rule:
    return Rule(
        workload="my-workload",
        name="my-rule",
        type=type,
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


def test_no_rules() -> None:
    rules = []
    account = Account(
        name="my-account",
        account_id="123412341234",
        cidr_ranges=CidrRanges(
            cidr_ranges=[CidrRange(region="eu-west-1", value="10.0.0.0/24")]
        ),
        rules=rules,
    )
    assert len(account.rules) == 0
    assert len(account.egress_rules) == 0
    assert len(account.inspection_rules) == 0


def test_inspection_rules() -> None:
    rules = [generate_rule(Rule.INSPECTION)]
    account = Account(
        name="my-account",
        account_id="123412341234",
        cidr_ranges=CidrRanges(
            cidr_ranges=[CidrRange(region="eu-west-1", value="10.0.0.0/8")]
        ),
        rules=rules,
    )
    assert len(account.rules) == 1
    assert len(account.egress_rules) == 0
    assert len(account.inspection_rules) == 1


def test_egress_rules() -> None:
    rules = [generate_rule(Rule.EGRESS)]
    account = Account(
        name="my-account",
        account_id="123412341234",
        cidr_ranges=CidrRanges(
            cidr_ranges=[CidrRange(region="eu-west-1", value="10.0.0.0/8")]
        ),
        rules=rules,
    )
    assert len(account.rules) == 1
    assert len(account.egress_rules) == 1
    assert len(account.inspection_rules) == 0
