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
        import re
        
        # Regex to capture rule names
        # Matches: default rule_name := ... | rule_name := ... | rule_name[...] := ...
        rule_pattern = re.compile(r'^\s*(?:default\s+)?([a-z_][a-z0-9_]*)(?:\[.+\])?\s*:=')

        for root, _, files in os.walk(self.policies_path):
            for file in files:
                if file.endswith(".rego"):
                    with open(os.path.join(root, file), 'r', encoding='utf-8') as f:
                        lines = f.readlines()
                        
                        current_metadata = {}
                        in_metadata = False
                        
                        for line in lines:
                            line = line.strip()
                            
                            # Start of metadata block
                            if line.startswith("# METADATA"):
                                current_metadata = {"custom": {}}
                                in_metadata = True
                                continue

                            if in_metadata:
                                if line.startswith("#"):
                                    # Parse metadata fields
                                    # Expected format: # key: value
                                    parts = line.lstrip("# ").split(":", 1)
                                    if len(parts) == 2:
                                        key = parts[0].strip()
                                        val = parts[1].strip()
                                        
                                        if key == "scope": current_metadata["scope"] = val
                                        elif key == "title": current_metadata["title"] = val
                                        elif key == "description": current_metadata["description"] = val
                                        elif key == "custom": pass # Start of custom block (YAML-like)
                                        elif key in ["severity", "threat", "requiredScopes"]:
                                            current_metadata[key] = val
                                        # Simple heuristic for list items in remediationSteps or threat
                                        elif key.startswith("-"):
                                             # This is very basic YAML parsing simulation
                                             # Ideally we should parse the whole comment block as YAML
                                             pass
                                else:
                                    # End of metadata block, look for rule name
                                    # Ignore empty lines
                                    if not line: continue
                                    
                                    match = rule_pattern.match(line)
                                    if match:
                                        rule_name = match.group(1)
                                        self.metadata_cache[rule_name] = current_metadata
                                    
                                    # Reset
                                    in_metadata = False
                                    current_metadata = {}

    def eval(self, input_data: Dict[str, Any], package: str = "repository") -> List[Dict[str, Any]]:
        if not self.opa_binary:
             raise Exception("OPA binary not configured.")

        cmd = [
            self.opa_binary,
            "eval",
            "-I", # input from stdin
            "-d", self.policies_path,
            f"data.{package}",
            "--format", "json"
        ]

        try:
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate(input=json.dumps(input_data))
            
            if process.returncode != 0:
                # OPA failure
                raise Exception(f"OPA execution failed: {stderr}")

            result = json.loads(stdout)
            
            violations = []
            if "result" in result and len(result["result"]) > 0:
                expressions = result["result"][0].get("expressions", [])
                if expressions:
                    package_eval = expressions[0].get("value", {})
                    for rule_name, value in package_eval.items():
                         if value is True: # Boolean violation
                              v = {"rule": rule_name, "details": None, "status": "FAILED"}
                              self._enrich_violation(v)
                              violations.append(v)
                         elif isinstance(value, list) and len(value) > 0: # Set violation
                              for detail in value:
                                  v = {"rule": rule_name, "details": detail, "status": "FAILED"}
                                  self._enrich_violation(v)
                                  violations.append(v)

            return violations

        except FileNotFoundError:
             raise Exception(f"OPA binary not found at {self.opa_binary}")
        except json.JSONDecodeError:
             raise Exception(f"Invalid JSON output from OPA: {stdout}")

    def _enrich_violation(self, violation: Dict[str, Any]):
        rule = violation["rule"]
        if rule in self.metadata_cache:
            meta = self.metadata_cache[rule]
            violation["policyName"] = meta.get("title", rule)
            violation["description"] = meta.get("description", "")
            violation["severity"] = meta.get("severity", "MEDIUM")
            # For remediation, we might need better parsing, but placeholder for now
            violation["remediationSteps"] = ["Check policy file for remediation steps."]


