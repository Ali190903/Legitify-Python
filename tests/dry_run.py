import sys
import os
import json

# Add project root to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from internal.collectors.repository_collector import RepositoryCollector
from internal.opa.opa_engine import OpaEngine
from internal.outputer.base_outputer import ConsoleOutputer
from internal.common.types import Repository

# Mock Client
class MockClient:
    def get_repositories(self, org):
        # Return a mock raw payload as if from GraphQL
        return [
            {
                "name": "insecure-repo",
                "id": "1",
                "url": "https://github.com/org/insecure-repo",
                "isPrivate": False, # Public
                "isArchived": False,
                "pushedAt": "2023-01-01T00:00:00Z", # Old
                "defaultBranchRef": {
                    "name": "main",
                    "branchProtectionRule": None # No protection
                },
                "collaborators": {"nodes": []}
            },
            {
                "name": "secure-repo",
                "id": "2",
                "url": "https://github.com/org/secure-repo",
                "isPrivate": True,
                "isArchived": False,
                "pushedAt": "2025-01-01T00:00:00Z", # Recent
                "defaultBranchRef": {
                    "name": "main",
                    "branchProtectionRule": {
                         "allowsDeletions": False,
                         "allowsForcePushes": False,
                         "requiresStatusChecks": True,
                         "requiresStrictStatusChecks": True,
                         "requiresCodeOwnerReviews": True,
                         "requiredApprovingReviewCount": 2,
                         "dismissesStaleReviews": True,
                         "requiresLinearHistory": True,
                         "requiresConversationResolution": True,
                         "requiresCommitSignatures": True,
                         "restrictsReviewDismissals": True,
                         "restrictsPushes": True 
                    }
                },
                 "collaborators": {"nodes": []}
            }
        ]

def run():
    print("Running dry run...")
    
    # 1. Collect (Mocked)
    client = MockClient()
    collector = RepositoryCollector(client)
    repos = collector.collect_all("mock-org")
    
    # 2. Opa
    policies_path = os.path.join(os.path.dirname(__file__), '..', 'policies')
    print(f"Using policies at: {policies_path}")
    
    try:
        engine = OpaEngine(policies_path)
    except Exception as e:
        print(f"Skipping OPA test: {e}")
        return

    all_violations = []
    
    for r in repos:
        input_data = {
            "repository": r.model_dump(by_alias=True)
        }
        # Defaults
        input_data["hooks"] = []
        input_data["collaborators"] = []
        
        # print(json.dumps(input_data, indent=2))
        
        violations = engine.eval(input_data, package="repository")
        for v in violations:
             v["repo"] = r.name
             all_violations.append(v)

    # 3. Output
    outputer = ConsoleOutputer()
    outputer.print_violations(all_violations)

if __name__ == "__main__":
    run()
