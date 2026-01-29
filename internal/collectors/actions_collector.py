from typing import List
from internal.clients.github_client import GitHubClient
from internal.common.types import OrganizationActions
from internal.common import namespace

class ActionsCollector:
    def __init__(self, client: GitHubClient):
        self.client = client

    def collect_total_entities(self, orgs: List[str]) -> int:
        return len(orgs)

    def collect(self, org: str) -> OrganizationActions:
        # Collects Actions settings for the organization
        actions_permissions = self.client.get_organization_actions_permissions(org)
        token_permissions = self.client.get_organization_workflow_permissions(org)
        
        return OrganizationActions(
            actions_permissions=actions_permissions,
            token_permissions=token_permissions
        )
