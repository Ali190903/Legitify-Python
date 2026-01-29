from typing import List
from internal.clients.github_client import GitHubClient
from internal.common.types import Member
from internal.collectors.base_collector import Collector

class MemberCollector(Collector):
    def __init__(self, client: GitHubClient, org: str):
        self.client = client
        self.org = org

    def get_namespace(self) -> str:
        return "member"

    def collect(self) -> List[Member]:
        raw_members = self.client.get_members(self.org)
        members = []
        
        for m in raw_members:
            # role is usually "ADMIN" or "MEMBER"
            is_admin = m.get("role") == "ADMIN"
            
            member = Member(
                login=m["login"],
                role=m.get("role", "MEMBER"),
                is_admin=is_admin,
                last_active=-1 
            )
            members.append(member)
            
        return members
