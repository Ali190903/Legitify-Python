from typing import Set, List

class Skipper:
    def __init__(self, ignore_file: str = None):
        self.ignored_policies: Set[str] = set()
        if ignore_file:
            self._load_from_file(ignore_file)

    def _load_from_file(self, path: str):
        try:
            with open(path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self.ignored_policies.add(line)
        except Exception as e:
            print(f"Warning: Failed to load ignore file {path}: {e}")

    def should_skip(self, policy_name: str) -> bool:
        return policy_name in self.ignored_policies
