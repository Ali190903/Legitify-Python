import sys
import os

print("Verifying Legitify Python Installation...")

try:
    # 1. Config
    from internal.common.config import ConfigManager
    cm = ConfigManager.get_instance()
    print("[OK] ConfigManager initialized")

    # 2. Clients
    from internal.clients.github_client import GitHubClient
    # Mock token
    client = GitHubClient("test_token")
    print("[OK] GitHubClient initialized")

    # 3. Collectors
    from internal.collectors.github.organization_collector import OrganizationCollector
    from internal.collectors.github.repository_collector import RepositoryCollector
    print("[OK] Collectors imported")

    # 4. OPA
    from internal.opa.opa_engine import OpaEngine
    from internal.opa.skipper import Skipper
    skipper = Skipper()
    print("[OK] OPA modules imported")

    # 5. Outputters
    from internal.outputer.base_outputer import ConsoleOutputer
    from internal.outputer.sarif_outputer import SarifOutputter
    out = SarifOutputter()
    print("[OK] Outputters imported")

    # 6. CLI
    from cli.analyze import analyze
    print("[OK] CLI imported")

    print("\nSUCCESS: All core modules verified structurally.")

except Exception as e:
    print(f"\nFAILED: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
