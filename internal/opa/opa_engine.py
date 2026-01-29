import json
import subprocess
import os
import shutil
from typing import List, Dict, Any

class OpaEngine:
    def __init__(self, policies_path: str):
        self.policies_path = policies_path
        self.opa_binary = shutil.which("opa")
        
        # Fallback to local opa.exe if not in PATH
        if not self.opa_binary:
            local_opa = os.path.join(os.getcwd(), "opa.exe")
            if os.path.exists(local_opa):
                self.opa_binary = local_opa

        if not self.opa_binary:
            raise Exception("OPA binary not found. Please install OPA or place opa.exe in the current directory.")
            
        self.metadata_cache = {}
        self._load_metadata()

    def _load_metadata(self):
        # Walk through policies directory and parse METADATA
        # Pattern: rule_name := ... or default rule_name := ...
        # Preceded by # METADATA blocks
        import re
        
        # Regex to capture rule names and their metadata blocks
        # This is a simple parser, might need more robustness.
        # We assume METADATA is right above the rule or default rule.
        
        for root, _, files in os.walk(self.policies_path):
            for file in files:
                if file.endswith(".rego"):
                    with open(os.path.join(root, file), 'r', encoding='utf-8') as f:
                        content = f.read()
                        
                        # Find all rules with metadata
                        # Look for # METADATA ... (lines) ... rule_name :=
                        # Using a state machine approach might be better than valid regex for multiline
                        
                        lines = content.split('\n')
                        current_metadata = {}
                        in_metadata = False
                        
                        for line in lines:
                            line = line.strip()
                            if line.startswith("# METADATA"):
                                current_metadata = {"custom": {}}
                                in_metadata = True
                            elif in_metadata and line.startswith("#"):
                                # Parse metadata fields
                                parts = line.lstrip("# ").split(":", 1)
                                if len(parts) == 2:
                                    key = parts[0].strip()
                                    val = parts[1].strip()
                                    if key == "scope": current_metadata["scope"] = val
                                    elif key == "title": current_metadata["title"] = val
                                    elif key == "description": current_metadata["description"] = val
                                    elif key == "custom": pass # Start of custom block
                                    elif key in ["severity", "threat", "remediationSteps", "requiredScopes"]:
                                        # These are usually indented under custom, but let's just grab them if they appear
                                        # Or better, handle indentation. 
                                        # For simplicity, we grab known keys.
                                        current_metadata[key] = val
                                    else:
                                        # Handle list items like remediationSteps
                                        if key.startswith("-"):
                                            pass 
                            elif in_metadata and not line.startswith("#"):
                                # End of metadata block, look for rule name
                                # default rule_name := ... or rule_name := ... or rule_name[...
                                # Ignore empty lines
                                if not line: continue
                                
                                match = re.search(r'(?:default\s+)?([a-z_][a-z0-9_]*)(?:\[.+\])?\s*:=', line)
                                if match:
                                    rule_name = match.group(1)
                                    self.metadata_cache[rule_name] = current_metadata
                                in_metadata = False
                                current_metadata = {}


    def eval(self, input_data: Dict[str, Any], package: str = "repository") -> List[Dict[str, Any]]:
        # OPA expects input as a JSON string or file. We'll use stdin.
        # Command: opa eval -I -d policies/ --input - "data.repository"
        
        cmd = [
            self.opa_binary,
            "eval",
            "-I", # input from stdin
            "-d", self.policies_path,
            f"data.{package}",
            "--format", "json"
        ]

        # Prepare input wrapped in "input" key if OPA doesn't wrap it automatically with -I?
        # Actually with --input or -I, the data provided is bound to 'input'.
        
        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        stdout, stderr = process.communicate(input=json.dumps(input_data))
        
        if process.returncode != 0:
            raise Exception(f"OPA Error: {stderr}")

        result = json.loads(stdout)
        
        # Parse violations from result
        # The result structure from OPA eval depends on the query.
        # "data.repository" returns the whole package evaluation.
        # We need to look for rules that evaluated to 'true' (if they represent violations like 'repository_not_maintained')
        
        violations = []
        if "result" in result and len(result["result"]) > 0:
            expressions = result["result"][0].get("expressions", [])
            if expressions:
                package_eval = expressions[0].get("value", {})
                for rule_name, value in package_eval.items():
                    # In Legitify policies, violations are usually booleans (true = violation) 
                    # or sets (for multi-value violations like webhooks).
                    
                     if value is True:
                          v = {"rule": rule_name, "details": None}
                          self._enrich_violation(v)
                          violations.append(v)
                     elif isinstance(value, list) and len(value) > 0:
                          # Set/Array of violations
                          for detail in value:
                              v = {"rule": rule_name, "details": detail}
                              self._enrich_violation(v)
                              violations.append(v)

        return violations

    def _enrich_violation(self, violation: Dict[str, Any]):
        rule = violation["rule"]
        if rule in self.metadata_cache:
            meta = self.metadata_cache[rule]
            violation["policyName"] = meta.get("title", rule)
            violation["description"] = meta.get("description", "")
            violation["severity"] = meta.get("severity", "MEDIUM")
            violation["remediationSteps"] = [meta.get("remediationSteps")] if isinstance(meta.get("remediationSteps"), str) else []
            # Note: Parsing lists from YAML-like comments needs better logic, but this is a start.

