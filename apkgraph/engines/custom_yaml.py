import os
import re
import yaml
from apkgraph.core.engine import BaseIntelligenceModule, SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO
from apkgraph.core.text_heuristics import MAX_STRING_LEN

class CustomYamlAnalyzer(BaseIntelligenceModule):
    """
    Custom YAML Rule Engine (Nuclei-style for APKs).
    Loads custom YAML rules to scan strings and decompiled classes.
    """

    def __init__(self, apk_data):
        super().__init__(apk_data)
        self.rules_path = apk_data.get("rules_path")
        self.rules = []
        self._load_rules()

    def _load_rules(self):
        if not self.rules_path or not os.path.exists(self.rules_path):
            return

        if os.path.isdir(self.rules_path):
            for filename in os.listdir(self.rules_path):
                if filename.endswith((".yaml", ".yml")):
                    filepath = os.path.join(self.rules_path, filename)
                    self._parse_rule_file(filepath)
        else:
            self._parse_rule_file(self.rules_path)

    def _parse_rule_file(self, filepath):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                rule_docs = yaml.safe_load_all(f)
                for doc in rule_docs:
                    if isinstance(doc, list):
                        for rule in doc:
                            if isinstance(rule, dict) and 'id' in rule and 'patterns' in rule:
                                self.rules.append(rule)
                    elif isinstance(doc, dict):
                        if 'id' in doc and 'patterns' in doc:
                            self.rules.append(doc)
        except Exception as e:
            # We silently ignore malformed YAML files in this engine
            pass

    def _map_severity(self, sev_str):
        mapping = {
            "critical": SEVERITY_CRITICAL,
            "high": SEVERITY_HIGH,
            "medium": SEVERITY_MEDIUM,
            "low": SEVERITY_LOW,
            "info": SEVERITY_INFO
        }
        return mapping.get(str(sev_str).lower(), SEVERITY_INFO)

    def analyze(self) -> list[dict]:
        if not self.rules:
            return []

        analysis = self.apk_data.get("analysis")
        if not analysis:
            return []

        findings = []
        seen = set()

        for string_analysis in analysis.get_strings():
            string_val = string_analysis.get_value()
            if not string_val or len(string_val) > MAX_STRING_LEN:
                continue

            locations = None

            for rule in self.rules:
                rule_id = rule.get('id', 'Custom Rule')
                severity = self._map_severity(rule.get('info', {}).get('severity', 'info'))
                patterns = rule.get('patterns', [])
                
                for pattern in patterns:
                    try:
                        matches = re.finditer(pattern, string_val, re.IGNORECASE)
                        for match in matches:
                            val = match.group(0)
                            if val in seen:
                                continue
                            seen.add(val)
                            
                            if locations is None:
                                locations = self._locations_for(string_analysis)
                                
                            findings.append({
                                "type": f"Custom YAML Rule: {rule_id}",
                                "value": val[:120],
                                "confidence": severity,
                                "locations": locations,
                                "description": rule.get('info', {}).get('description', 'Detected via custom YAML rule')
                            })
                    except re.error:
                        continue # Invalid regex pattern in YAML

        self.findings = findings
        return self.findings

    @staticmethod
    def _locations_for(string_analysis) -> list[str]:
        locations = []
        try:
            for _, method in string_analysis.get_xref_from():
                try:
                    locations.append(f"{method.class_name}->{method.name}{method.descriptor}")
                except Exception:
                    continue
        except Exception:
            pass
        return locations
