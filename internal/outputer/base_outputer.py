import json
from rich.console import Console
from rich.table import Table
from typing import List, Dict

class ConsoleOutputer:
    def __init__(self, output_format: str = "human"):
        self.console = Console()
        self.output_format = output_format

    def print_violations(self, violations: List[Dict]):
        if self.output_format == "json":
            print(json.dumps(violations, indent=2))
            return

        if self.output_format == "markdown":
            self._print_markdown(violations)
            return

        if not violations:
            self.console.print("[bold green]No violations found! Great job![/bold green]")
            return

        # Group by namespace (repository/org)
        # Actually a flat table is fine closely mimicking Legitify Go output
        
        table = Table(title="Legitify Security Analysis Results")
        table.add_column("Target", style="cyan", no_wrap=True)
        table.add_column("Severity", style="red")
        table.add_column("Policy", style="magenta")
        table.add_column("Details", style="white")

        for v in violations:
            target = v.get("target", "N/A")
            policy_name = v.get("policyName", v.get("rule", "Unknown"))
            severity = v.get("severity", "MEDIUM") 
            details = v.get("details")
            
            detail_str = ""
            if details:
                if isinstance(details, dict):
                     detail_str = ", ".join([f"{k}={v}" for k,v in details.items()])
                else:
                     detail_str = str(details)
            
            table.add_row(target, severity, policy_name, detail_str)

        self.console.print(table)
        self.console.print(f"\n[bold red]Total Violations: {len(violations)}[/bold red]")

    def _print_markdown(self, violations: List[Dict]):
        if not violations:
            print("No violations found.")
            return

        print("# Legitify Security Analysis Results\n")
        print("| Target | Severity | Policy | Details |")
        print("|---|---|---|---|")
        
        for v in violations:
            target = v.get("target", "N/A")
            policy_name = v.get("policyName", v.get("rule", "Unknown"))
            severity = v.get("severity", "MEDIUM")
            details = v.get("details")
            
            detail_str = ""
            if details:
                if isinstance(details, dict):
                     detail_str = ", ".join([f"{k}={v}" for k,v in details.items()])
                else:
                     detail_str = str(details)
            
            # Escape pipes in markdown table
            detail_str = detail_str.replace("|", "\\|")
            
            print(f"| {target} | {severity} | {policy_name} | {detail_str} |")

