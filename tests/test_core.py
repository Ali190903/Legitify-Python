import pytest
from unittest.mock import MagicMock, patch
from internal.collectors.organization_collector import OrganizationCollector
from internal.collectors.member_collector import MemberCollector
from internal.opa.opa_engine import OpaEngine

def test_organization_collector():
    mock_client = MagicMock()
    mock_client.get_organization_details.return_value = {
        "login": "test-org",
        "name": "Test Org",
        "requiresTwoFactorAuthentication": True,
        "samlIdentityProvider": {"ssoUrl": "http://sso"}
    }
    mock_client.get_organization_webhooks.return_value = []

    collector = OrganizationCollector(mock_client)
    org = collector.collect("test-org")

    assert org.login == "test-org"
    assert org.two_factor_requirement_enabled is True
    assert org.saml_enabled is True

def test_member_collector():
    mock_client = MagicMock()
    mock_client.get_members.return_value = [
        {"login": "user1", "role": "ADMIN"},
        {"login": "user2", "role": "MEMBER"}
    ]

    collector = MemberCollector(mock_client)
    members = collector.collect("test-org")

    assert len(members) == 2
    assert members[0].is_admin is True
    assert members[1].is_admin is False

@patch("subprocess.Popen")
@patch("shutil.which")
def test_opa_engine(mock_which, mock_popen):
    mock_which.return_value = "/usr/bin/opa"
    
    mock_process = MagicMock()
    mock_process.communicate.return_value = ('{"result": [{"expressions": [{"value": {"rule1": true}}]}]}', '')
    mock_process.returncode = 0
    mock_popen.return_value = mock_process

    engine = OpaEngine("/policies")
    violations = engine.eval({"some": "input"})

    assert len(violations) == 1
    assert violations[0]["rule"] == "rule1"
