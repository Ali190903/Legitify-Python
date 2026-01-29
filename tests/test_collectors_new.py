import pytest
from unittest.mock import MagicMock
from internal.collectors.actions_collector import ActionsCollector
from internal.collectors.runners_collector import RunnersCollector

def test_actions_collector():
    mock_client = MagicMock()
    mock_client.get_organization_actions_permissions.return_value = {
        "enabled_repositories": "selected",
        "allowed_actions": "selected"
    }
    mock_client.get_organization_workflow_permissions.return_value = {
        "default_workflow_permissions": "read",
        "can_approve_pull_request_reviews": False
    }

    collector = ActionsCollector(mock_client)
    actions = collector.collect("test-org")

    assert actions.actions_permissions["enabled_repositories"] == "selected"
    assert actions.token_permissions["default_workflow_permissions"] == "read"

def test_runners_collector():
    mock_client = MagicMock()
    mock_client.get_organization_runner_groups.return_value = [
        {
            "id": 1,
            "name": "Default",
            "visibility": "all",
            "allows_public_repositories": True,
            "default": True,
            "runners_url": "url",
            "inherited": False
        }
    ]

    collector = RunnersCollector(mock_client)
    groups = collector.collect("test-org")

    assert len(groups) == 1
    assert groups[0].name == "Default"
    assert groups[0].allows_public_repositories is True
