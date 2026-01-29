from enum import Enum
from typing import List

class Namespace(str, Enum):
    ENTERPRISE = "enterprise"
    ORGANIZATION = "organization"
    REPOSITORY = "repository"
    MEMBER = "member"
    ACTIONS = "actions"
    RUNNER_GROUP = "runner_group"

ALL_NAMESPACES = [
    Namespace.ORGANIZATION,
    Namespace.ENTERPRISE,
    Namespace.REPOSITORY,
    Namespace.MEMBER,
    Namespace.ACTIONS,
    Namespace.RUNNER_GROUP,
]

def validate_namespaces(namespaces: List[str]) -> None:
    for ns in namespaces:
        if ns not in [n.value for n in ALL_NAMESPACES]:
            raise ValueError(f"invalid namespace {ns}")
