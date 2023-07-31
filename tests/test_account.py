from typing import List

from aws_network_firewall.account import Account
from aws_network_firewall.cidr_range import CidrRange
from aws_network_firewall.cidr_ranges import CidrRanges
from aws_network_firewall.destination import Destination
from aws_network_firewall.rule import Rule
from aws_network_firewall.source import Source


def generate_account(rules: List[Rule]) -> Account:
    return Account(
        name="my-account",
        account_id="123412341234",
        cidr_ranges=CidrRanges(
            cidr_ranges=[CidrRange(region="eu-west-1", value="10.0.0.0/8")]
        ),
        rules=rules,
    )


def generate_rule(type: str, region: str) -> Rule:
    return Rule(
        workload="my-workload",
        name="my-rule",
        region=region,
        type=type,
        description="My description",
        sources=[Source(description="my source", cidr="10.0.0.0/24")],
        destinations=[
            Destination(
                description="my destination",
                protocol="TCP",
                port=443,
                cidr=None,
                endpoint=None,
                message=None,
                tls_versions=[],
            )
        ],
    )


outbound_xebia = Destination(
    description="Allow outbound connectivity to xebia.com",
    protocol="TCP",
    port=443,
    cidr=None,
    endpoint="xebia.com",
    message=None,
    tls_versions=[],
)


def test_no_rules() -> None:
    rules = []
    account = generate_account(rules=rules)
    assert len(account.rules) == 0
    assert len(account.egress_rules) == 0
    assert len(account.inspection_rules) == 0


def test_inspection_rules() -> None:
    rules = [generate_rule(Rule.INSPECTION, region="eu-west-1")]
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
    rules = [generate_rule(Rule.EGRESS, region="eu-west-1")]
    account = generate_account(rules=rules)
    assert len(account.rules) == 1
    assert len(account.egress_rules) == 1
    assert len(account.inspection_rules) == 0


def test_rules_resolve_single_region_egress() -> None:
    rules = [generate_rule(Rule.EGRESS, region="eu-west-1")]
    account = generate_account(rules=rules)
    assert len(account.rules) == 1
    assert len(account.egress_rules) == 1
    assert len(account.inspection_rules) == 0
    assert "eu-west-1" in account.regions


def test_rules_resolve_2_regions_egress() -> None:
    rules = [
        generate_rule(Rule.EGRESS, region="eu-west-1"),
        generate_rule(Rule.EGRESS, region="eu-central-1"),
    ]
    account = generate_account(rules=rules)
    assert len(account.rules) == 2
    assert len(account.egress_rules) == 2
    assert len(account.inspection_rules) == 0
    assert "eu-west-1" in account.regions
    assert "eu-central-1" in account.regions

    rules = account.rules_by_region("eu-west-1")
    assert len(rules) == 1
    assert len(rules.egress_rules) == 1
    assert len(rules.inspection_rules) == 0

    rules = account.rules_by_region("eu-central-1")
    assert len(rules) == 1
    assert len(rules.egress_rules) == 1
    assert len(rules.inspection_rules) == 0


def test_rules_resolve_single_source_region_inspection() -> None:
    rules = [generate_rule(Rule.INSPECTION, region="eu-west-1")]
    account = generate_account(rules=rules)
    assert len(account.rules) == 1
    assert len(account.egress_rules) == 0
    assert len(account.inspection_rules) == 1
    assert "eu-west-1" in account.regions

    rules = account.rules_by_region("eu-west-1")
    assert len(rules) == 1
    assert len(rules.egress_rules) == 0
    assert len(rules.inspection_rules) == 1

    rules = account.rules_by_region("eu-central-1")
    assert len(rules) == 0
    assert len(rules.egress_rules) == 0
    assert len(rules.inspection_rules) == 0


def test_rules_resolve_2_source_regions_inspection() -> None:
    rules = [
        generate_rule(Rule.INSPECTION, region="eu-west-1"),
        generate_rule(Rule.INSPECTION, region="eu-central-1"),
    ]
    account = generate_account(rules=rules)
    assert len(account.rules) == 2
    assert len(account.egress_rules) == 0
    assert len(account.inspection_rules) == 2
    assert "eu-west-1" in account.regions
    assert "eu-central-1" in account.regions

    rules = account.rules_by_region("eu-west-1")
    assert len(rules) == 1
    assert len(rules.egress_rules) == 0
    assert len(rules.inspection_rules) == 1

    rules = account.rules_by_region("eu-central-1")
    assert len(rules) == 1
    assert len(rules.egress_rules) == 0
    assert len(rules.inspection_rules) == 1
