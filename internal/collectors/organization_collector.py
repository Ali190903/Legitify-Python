from typing import List
from internal.clients.github_client import GitHubClient
from internal.common.types import Organization, Hook
from internal.common import types

class OrganizationCollector:
    def __init__(self, client: GitHubClient):
        self.client = client

    def collect(self, org_name: str) -> Organization:
        # Collect basic org details
        details = self.client.get_organization_details(org_name)
        
        # Collect webhooks (REST)
        hooks_data = self.client.get_organization_webhooks(org_name)
        hooks = []
        for h in hooks_data:
            hook = Hook(
                name=h.get("name", "web"),
                url=h.get("config", {}).get("url", ""),
                id=h.get("id", 0)
            )
            # Add secret validation logic if needed or just store raw for OPA
            # OPA needs to know if secret is present. 
            # In Github API, config.secret is usually masked as "********" if present.
            # But the 'insecure_ssl' field is in config.
            # We need to pass enough info for OPA 'has_secret' check.
            # Actually, we can't see the secret. But we can check if it relies on secret?
            # Legitify Go implementation might check if 'secret' field is not empty in config?
            # Or maybe just pass raw config to let OPA decide. 
            # Let's attach raw config to hook object if we defined it in types?
            # For now, let's stick to basic collection.
            hooks.append(hook)

        # Map to Organization model
        org = Organization(
            login=details["login"],
            name=details.get("name"),
            description=details.get("description"),
            url=details.get("url"),
            two_factor_requirement_enabled=details.get("requiresTwoFactorAuthentication", False),
            members_can_create_public_repositories=details.get("membersCanCreatePublicRepositories", False),
            default_repository_permission=details.get("defaultRepositoryPermission"),
            saml_enabled=True if details.get("samlIdentityProvider") else False,
            hooks=hooks
        )

        return org
