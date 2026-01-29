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

        if not violations:
            self.console.print("[bold green]No violations found! Great job![/bold green]")
            return

        # Group by namespace (repository/org)
        # Actually a flat table is fine closely mimicking Legitify Go output
        
        table = Table(title="Security Violations Analysis Results")
        table.add_column("Target", style="cyan", no_wrap=True)
        table.add_column("Rule", style="magenta")
        table.add_column("Details", style="white")

        for v in violations:
            target = v.get("target", "N/A")
            rule = v.get("rule", "Unknown")
            details = v.get("details")
            
            detail_str = ""
            if details:
                if isinstance(details, dict):
                     detail_str = ", ".join([f"{k}={v}" for k,v in details.items()])
                else:
                     detail_str = str(details)
            
            table.add_row(target, rule, detail_str)

        self.console.print(table)
        self.console.print(f"\n[bold red]Total Violations: {len(violations)}[/bold red]")
