import requests
import os

class GitHubClient:
    def __init__(self, token: str):
        self.token = token
        self.endpoint = "https://api.github.com/graphql"
        self.rest_endpoint = "https://api.github.com"

    def query(self, query: str, variables: dict = None):
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }
        json_data = {"query": query, "variables": variables or {}}
        response = requests.post(self.endpoint, json=json_data, headers=headers)
        response.raise_for_status()
        data = response.json()
        if "errors" in data:
            raise Exception(f"GraphQL Error: {data['errors']}")
        return data

    def get_repositories(self, org_name: str):
        query = """
        query($login: String!, $cursor: String) {
            organization(login: $login) {
                repositories(first: 50, after: $cursor, isArchived: false) {
                    pageInfo {
                        hasNextPage
                        endCursor
                    }
                    nodes {
                        name
                        id
                        url
                        isPrivate
                        isArchived
                        pushedAt
                        allowForking
                        description
                        defaultBranchRef {
                            name
                            branchProtectionRule {
                                allowsDeletions
                                allowsForcePushes
                                requiresStatusChecks
                                requiresStrictStatusChecks
                                requiresCodeOwnerReviews
                                requiredApprovingReviewCount
                                dismissesStaleReviews
                                requiresLinearHistory
                                requiresConversationResolution
                                requiresCommitSignatures
                                restrictsReviewDismissals
                                restrictsPushes
                            }
                        }
                        viewerPermission
                        collaborators(first: 100) {
                            nodes {
                                login
                                permissions {
                                    admin
                                    maintain
                                    push
                                    triage
                                    pull
                                }
                            }
                        }
                        webhooks(first: 20) {
                            nodes {
                                id
                                url
                                active
                            }
                        }
                    }
                }
            }
        }
        """
        
        all_repos = []
        cursor = None
        has_next = True

        while has_next:
            variables = {"login": org_name, "cursor": cursor}
            data = self.query(query, variables)
            org_data = data["data"]["organization"]
            
            if not org_data: # Handle case where org might not be found or empty
                 break

            repos = org_data["repositories"]
            all_repos.extend(repos["nodes"])
            
            has_next = repos["pageInfo"]["hasNextPage"]
            cursor = repos["pageInfo"]["endCursor"]

        return all_repos

    def get_organization_details(self, org_name: str) -> dict:
        query = """
        query($login: String!) {
            organization(login: $login) {
                name
                login
                description
                url
                requiresTwoFactorAuthentication
                membersCanCreatePublicRepositories
                defaultRepositoryPermission
                samlIdentityProvider {
                    ssoUrl
                }
            }
        }
        """
        variables = {"login": org_name}
        data = self.query(query, variables)
        return data["data"]["organization"]

    def get_members(self, org_name: str) -> list:
        query = """
        query($login: String!, $cursor: String) {
            organization(login: $login) {
                membersWithRole(first: 50, after: $cursor) {
                    pageInfo {
                        hasNextPage
                        endCursor
                    }
                    nodes {
                        login
                        name
                        email
                    }
                    edges {
                        role
                        node {
                            login
                        }
                    }
                }
            }
        }
        """
        
        all_members = []
        cursor = None
        has_next = True

        while has_next:
            variables = {"login": org_name, "cursor": cursor}
            data = self.query(query, variables)
            org_data = data["data"]["organization"]
            
            if not org_data:
                 break

            members = org_data["membersWithRole"]
            
            # Map edges to get roles
            # edges contains role and node
            for edge in members["edges"]:
                role = edge["role"]
                node = edge["node"]
                # Find the full node data from nodes list (or just use edge.node if it has everything, 
                # but in this query 'nodes' and 'edges' are siblings. Let's actully optimize query to just use edges)
                # Actually edges { node { ... } role } is better.
                member_data = {
                    "login": node["login"],
                    "role": role
                    # We can fetch other fields if I update the query structure in loop implementation below
                }
                all_members.append(member_data)
            
            has_next = members["pageInfo"]["hasNextPage"]
            cursor = members["pageInfo"]["endCursor"]

        return all_members

    # REST API Helpers
    def _get_rest(self, path: str):
        url = f"{self.rest_endpoint}{path}"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github.v3+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 204: # No content, sometimes used for boolean checks
            return True
        return None

    def get_organization_webhooks(self, org_name: str) -> list:
        # Use common REST helper
        data = self._get_rest(f"/orgs/{org_name}/hooks")
        return data if isinstance(data, list) else []

    def get_repository_secrets(self, owner: str, repo: str) -> list:
        # returns list of secrets dicts
        resp = self._get_rest(f"/repos/{owner}/{repo}/actions/secrets")
        return resp.get("secrets", []) if resp else []

    def get_actions_permissions(self, owner: str, repo: str) -> dict:
        return self._get_rest(f"/repos/{owner}/{repo}/actions/permissions") or {}

    def get_rulesets(self, owner: str, repo: str) -> list:
        return self._get_rest(f"/repos/{owner}/{repo}/rulesets") or []

    def check_vulnerability_alerts(self, owner: str, repo: str) -> bool:
        url = f"{self.rest_endpoint}/repos/{owner}/{repo}/vulnerability-alerts"
        headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/vnd.github.v3+json"}
        resp = requests.get(url, headers=headers)
        return resp.status_code == 204

    def get_security_analysis(self, owner: str, repo: str) -> dict:
        # Fetch full repo details via REST to get security_and_analysis
        data = self._get_rest(f"/repos/{owner}/{repo}")
        if data and "security_and_analysis" in data:
            return data["security_and_analysis"]
        return {}

