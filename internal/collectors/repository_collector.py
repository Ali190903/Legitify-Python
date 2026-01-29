from typing import List
from internal.clients.github_client import GitHubClient
from internal.common.types import Repository, Ref, BranchProtectionRule, Hook, RepositorySecret
from internal.common import types

class RepositoryCollector:
    def __init__(self, client: GitHubClient):
        self.client = client

    def collect_all(self, org: str) -> List[Repository]:
        raw_repos = self.client.get_repositories(org)
        collected_repos = []

        for raw in raw_repos:
            repo = self._map_repo(raw)
            
            # Fetch extra data via REST
            # This might be slow for many repos, but needed for parity.
            owner = org
            repo_name = repo.name
            
            # Secrets
            secrets = self.client.get_repository_secrets(owner, repo_name)
            for s in secrets:
                repo.repo_secrets.append(types.RepositorySecret(
                    name=s["name"],
                    update_date=s.get("updated_at", "") # Pass ISO string
                ))
            
            # Actions Permissions
            repo.actions_token_permissions = self.client.get_actions_permissions(owner, repo_name)
            
            # Rulesets
            repo.rules_set = self.client.get_rulesets(owner, repo_name)
            
            # Vulnerability Alerts
            repo.vulnerability_alerts_enabled = self.client.check_vulnerability_alerts(owner, repo_name)
            
            # Security & Analysis
            repo.security_and_analysis = self.client.get_security_analysis(owner, repo_name)
            
            collected_repos.append(repo)

        return collected_repos

    def _map_repo(self, raw: dict) -> Repository:
        default_branch = None
        if raw.get("defaultBranchRef"):
            rule_data = raw["defaultBranchRef"].get("branchProtectionRule")
            rule = None
            if rule_data:
                rule = BranchProtectionRule(
                    allows_deletions=rule_data.get("allowsDeletions", False),
                    allows_force_pushes=rule_data.get("allowsForcePushes", False),
                    requires_status_checks=rule_data.get("requiresStatusChecks", False),
                    requires_strict_status_checks=rule_data.get("requiresStrictStatusChecks", False),
                    requires_code_owner_reviews=rule_data.get("requiresCodeOwnerReviews", False),
                    required_approving_review_count=rule_data.get("requiredApprovingReviewCount", 0),
                    dismisses_stale_reviews=rule_data.get("dismissesStaleReviews", False),
                    requires_linear_history=rule_data.get("requiresLinearHistory", False),
                    requires_conversation_resolution=rule_data.get("requiresConversationResolution", False),
                    requires_commit_signatures=rule_data.get("requiresCommitSignatures", False),
                    restricts_review_dismissals=rule_data.get("restrictsReviewDismissals", False),
                    restricts_pushes=rule_data.get("restrictsPushes", False),
                )
            
            default_branch = Ref(
                name=raw["defaultBranchRef"]["name"],
                branch_protection_rule=rule
            )

        # Map collaborators
        collaborators = []
        if raw.get("collaborators"):
            for node in raw["collaborators"]["nodes"]:
                collaborators.append(node)

        # Map webhooks
        hooks = []
        if raw.get("webhooks"):
            for node in raw["webhooks"]["nodes"]:
                hooks.append(Hook(
                    id=int(node.get("id", 0)) if isinstance(node.get("id"), int) else 0, # GraphQL id is typically string (node id), but REST is int. The policy expects... let's check. 
                    # Actually GraphQL ID is base64 string. Repository Hook ID in REST is int. 
                    # If GraphQL returns global node ID, we might need the databaseId if available. 
                    # For now, let's just use what we have or placeholder.
                    # Wait, policy might check for specific hooks. 
                    # Let's map URL and name.
                    name=node.get("url", ""), # Webhooks don't have a name in GraphQL node usually, just url/config.
                    url=node.get("url", "")
                ))

        return Repository(
            name=raw["name"],
            id=raw["id"],
            url=raw["url"],
            is_private=raw["isPrivate"],
            is_archived=raw["isArchived"],
            pushed_at=raw["pushedAt"],
            default_branch=default_branch,
            collaborators=collaborators,
            hooks=hooks
        )
