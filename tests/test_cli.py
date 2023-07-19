import os.path

from unittest.mock import patch, MagicMock
from click.testing import CliRunner
from landingzone_organization import Organization

from aws_network_firewall.cli import cli


def test_main() -> None:
    runner = CliRunner()
    result = runner.invoke(cli)

    assert result.exit_code == 0


def test_check() -> None:
    config_path = os.path.join(os.path.dirname(__file__), "workloads")
    runner = CliRunner()
    result = runner.invoke(cli, ["check", config_path])

    assert result.exit_code == 0


def test_update_docs() -> None:
    template_path = os.path.join(
        os.path.dirname(__file__), "workload-firewall-rules.jinja"
    )
    config_path = os.path.join(os.path.dirname(__file__), "workloads")
    runner = CliRunner()
    result = runner.invoke(cli, ["update", "docs", template_path, config_path])

    assert result.exit_code == 0


def test_check_invalid_path() -> None:
    config_path = os.path.join(os.path.dirname(__file__), "non-existing-folder")
    runner = CliRunner()
    result = runner.invoke(cli, ["check", config_path])
    assert "non-existing-folder is not a valid path" in result.output

    assert result.exit_code == 1


def test_check_invalid_info() -> None:
    config_path = os.path.join(
        os.path.dirname(__file__), "invalid-schemas/invalid-info"
    )
    runner = CliRunner()
    result = runner.invoke(cli, ["check", config_path])
    assert (
        f"In {config_path}/info.yaml we detected the following violation:"
        in result.output
    )
    assert result.exit_code == 1


def test_check_invalid_environment() -> None:
    config_path = os.path.join(
        os.path.dirname(__file__), "invalid-schemas/invalid-environment"
    )
    runner = CliRunner()
    result = runner.invoke(cli, ["check", config_path])
    assert (
        f"In {config_path}/development.yaml we detected the following violation:"
        in result.output
    )

    assert result.exit_code == 1
