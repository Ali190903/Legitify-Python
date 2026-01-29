import json
from typing import List, Dict, Any

class SarifOutputter:
    def __init__(self):
        pass

    def print_violations(self, violations: List[Dict]):
        sarif_log = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "legitify",
                            "informationUri": "https://github.com/Legit-Labs/legitify",
                            "rules": []
                        }
                    },
                    "results": []
                }
            ]
        }

        rules_map = {}
        results = []

        for v in violations:
            rule_id = v.get("rule", "unknown")
            policy_name = v.get("policyName", rule_id)
            description = v.get("description", "")
            severity = v.get("severity", "medium").lower()

            # Map severity to SARIF level
            level = "warning"
            if severity == "high" or severity == "critical":
                level = "error"
            elif severity == "low":
                level = "note"

            # Add rule if not exists
            if rule_id not in rules_map:
                rules_map[rule_id] = {
                    "id": rule_id,
                    "name": policy_name,
                    "shortDescription": {
                        "text": policy_name
                    },
                    "fullDescription": {
                        "text": description
                    },
                    "defaultConfiguration": {
                        "level": level
                    }
                }

            # Create result
            target = v.get("target", "unknown")
            result = {
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": f"Policy '{policy_name}' failed for {target}. Details: {v.get('details')}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": target # Placeholder, ideally file path or URL
                            }
                        }
                    }
                ]
            }
            results.append(result)

        sarif_log["runs"][0]["tool"]["driver"]["rules"] = list(rules_map.values())
        sarif_log["runs"][0]["results"] = results

        print(json.dumps(sarif_log, indent=2))
