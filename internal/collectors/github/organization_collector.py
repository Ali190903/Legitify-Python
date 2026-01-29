from typing import List
from internal.clients.github_client import GitHubClient
from internal.common.types import Organization, Hook, OrganizationSecret
from internal.collectors.base_collector import Collector

class OrganizationCollector(Collector):
    def __init__(self, client: GitHubClient, org: str):
        self.client = client
        self.org = org

    def get_namespace(self) -> str:
        return "organization"

    def collect(self) -> List[Organization]:
        # Collect basic org details
        details = self.client.get_organization_details(self.org)
        
        # Collect webhooks (REST)
        hooks_data = self.client.get_organization_webhooks(self.org)
        hooks = []
        for h in hooks_data:
            hooks.append(Hook(
                name=h.get("name", "web"),
                url=h.get("config", {}).get("url", ""),
                id=h.get("id", 0)
            ))

        # Collect Organization Secrets
        secrets_data = self.client.get_organization_secrets(self.org)
        org_secrets = []
        for s in secrets_data:
            org_secrets.append(OrganizationSecret(
                name=s["name"],
                update_date=s.get("updated_at", "")
            ))

        # Map to Organization model
        org_obj = Organization(
            login=details["login"],
            name=details.get("name"),
            description=details.get("description"),
            url=details.get("url"),
            two_factor_requirement_enabled=details.get("requiresTwoFactorAuthentication", False),
            members_can_create_public_repositories=details.get("membersCanCreatePublicRepositories", False),
            default_repository_permission=details.get("defaultRepositoryPermission"),
            saml_enabled=True if details.get("samlIdentityProvider") else False,
            hooks=hooks,
            organization_secrets=org_secrets
        )

        return [org_obj]
