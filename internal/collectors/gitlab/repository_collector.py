from typing import List
from internal.collectors.base_collector import Collector
from internal.common.types import GitLabProject

class RepositoryCollector(Collector):
    def get_namespace(self) -> str:
        return "repository"

    def collect(self) -> List[GitLabProject]:
        return self.client.get_projects()
