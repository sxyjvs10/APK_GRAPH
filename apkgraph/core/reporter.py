import json
import os

class ReportGenerator:
    def __init__(self, data):
        self.data = data

    def generate_json(self, output_path):
        with open(output_path, 'w') as f:
            json.dump(self.data, f, indent=4)
        print(f"[+] JSON report generated: {output_path}")

    def generate_markdown(self, output_path):
        md = f"# APKGraph Analysis Report\n\n"
        md += f"## Risk Score: {self.data['risk']['score']} ({self.data['risk']['rating']})\n\n"
        
        md += "## Predicted Attack Paths\n"
        for path in self.data['attack_paths']:
            md += f"### {path['name']}\n"
            md += f"- **Description:** {path['description']}\n"
            md += f"- **Confidence:** {path['confidence']}\n"
            md += f"- **Steps:** {' -> '.join(path['steps'])}\n\n"

        md += "## Findings\n"
        for module, findings in self.data['findings'].items():
            md += f"### {module}\n"
            md += "```json\n"
            md += json.dumps(findings, indent=2)
            md += "\n```\n\n"

        with open(output_path, 'w') as f:
            f.write(md)
        print(f"[+] Markdown report generated: {output_path}")
