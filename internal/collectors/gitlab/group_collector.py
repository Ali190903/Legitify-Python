from typing import List
from internal.collectors.base_collector import Collector
from internal.common.types import GitLabGroup

class GroupCollector(Collector):
    def get_namespace(self) -> str:
        return "organization"

    def collect(self) -> List[GitLabGroup]:
        return self.client.get_groups()
