from typing import List
from internal.clients.github_client import GitHubClient
from internal.common.types import RunnerGroup
from internal.common import namespace

class RunnersCollector:
    def __init__(self, client: GitHubClient):
        self.client = client

    def collect_total_entities(self, orgs: List[str]) -> int:
        # Determining total entities might require fetching them first if we count groups.
        # For simplicity, similar to Go, we might rely on the implementation or just count orgs if it's 1-to-many.
        # But Go actually counts total groups.
        # For now return 0 or implement pre-fetch if needed.
        return 0 

    def collect(self, org: str) -> List[RunnerGroup]:
        raw_groups = self.client.get_organization_runner_groups(org)
        collected_groups = []
        
        for rg in raw_groups:
            collected_groups.append(RunnerGroup(**rg))
            
        return collected_groups
