from typing import List
from internal.clients.github_client import GitHubClient
from internal.common.types import OrganizationActions
from internal.collectors.base_collector import Collector

class ActionsCollector(Collector):
    def __init__(self, client: GitHubClient, org: str):
        self.client = client
        self.org = org

    def get_namespace(self) -> str:
        return "actions"

    def collect(self) -> List[OrganizationActions]:
        # Collects Actions settings for the organization
        actions_permissions = self.client.get_organization_actions_permissions(self.org)
        token_permissions = self.client.get_organization_workflow_permissions(self.org)
        
        # Return as a list for consistency
        return [OrganizationActions(
            actions_permissions=actions_permissions,
            token_permissions=token_permissions
        )]
