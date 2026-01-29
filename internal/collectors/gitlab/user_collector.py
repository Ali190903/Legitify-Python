from typing import List
from internal.collectors.base_collector import Collector
from internal.common.types import GitLabMember

class UserCollector(Collector):
    def get_namespace(self) -> str:
        return "member"

    def collect(self) -> List[GitLabMember]:
        return self.client.get_users()
