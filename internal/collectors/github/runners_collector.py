from typing import List
from internal.clients.github_client import GitHubClient
from internal.common.types import RunnerGroup
from internal.collectors.base_collector import Collector

class RunnersCollector(Collector):
    def __init__(self, client: GitHubClient, org: str):
        self.client = client
        self.org = org

    def get_namespace(self) -> str:
        return "runner_group"

    def collect(self) -> List[RunnerGroup]:
        raw_groups = self.client.get_organization_runner_groups(self.org)
        collected_groups = []
        
        for rg in raw_groups:
            collected_groups.append(RunnerGroup(**rg))
            
        return collected_groups
