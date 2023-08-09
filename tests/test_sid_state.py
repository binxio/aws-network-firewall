from aws_network_firewall.sid_state import SidState


def test_state_100_200() -> None:
    state = SidState("100-200")

    assert state.allocate_sid("Egress", "eu-west-1") == 100
    assert state.allocate_sid("Egress", "eu-west-1") == 101
    assert state.allocate_sid("Egress", "eu-west-1") == 102
    assert state.allocate_sid("Egress", "eu-central-1") == 100
    assert state.allocate_sid("Egress", "eu-central-1") == 101
    assert state.allocate_sid("Egress", "eu-central-1") == 102
    assert state.allocate_sid("Inspection", "eu-west-1") == 100
    assert state.allocate_sid("Inspection", "eu-west-1") == 101
    assert state.allocate_sid("Inspection", "eu-west-1") == 102
    assert state.allocate_sid("Inspection", "eu-central-1") == 100
    assert state.allocate_sid("Inspection", "eu-central-1") == 101
    assert state.allocate_sid("Inspection", "eu-central-1") == 102


def test_state_500_600() -> None:
    state = SidState("500-600")

    assert state.allocate_sid("Egress", "eu-west-1") == 500
    assert state.allocate_sid("Egress", "eu-west-1") == 501
    assert state.allocate_sid("Egress", "eu-west-1") == 502
    assert state.allocate_sid("Egress", "eu-central-1") == 500
    assert state.allocate_sid("Egress", "eu-central-1") == 501
    assert state.allocate_sid("Egress", "eu-central-1") == 502
    assert state.allocate_sid("Inspection", "eu-west-1") == 500
    assert state.allocate_sid("Inspection", "eu-west-1") == 501
    assert state.allocate_sid("Inspection", "eu-west-1") == 502
    assert state.allocate_sid("Inspection", "eu-central-1") == 500
    assert state.allocate_sid("Inspection", "eu-central-1") == 501
    assert state.allocate_sid("Inspection", "eu-central-1") == 502
