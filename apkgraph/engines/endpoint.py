import re
from apkgraph.core.engine import BaseIntelligenceModule

class EndpointAnalyzer(BaseIntelligenceModule):
    def __init__(self, apk_data):
        super().__init__(apk_data)
        self.url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
        self.graphql_pattern = r'(?i)query|mutation|subscription'

    def analyze(self):
        analysis = self.apk_data['analysis']
        endpoint_findings = {
            "urls": set(),
            "graphql": False,
            "detected_sdks": []
        }

        for string_analysis in analysis.get_strings():
            string = string_analysis.get_value()
            # URL Extraction
            urls = re.findall(self.url_pattern, string)
            for url in urls:
                endpoint_findings["urls"].add(url)
            
            # GraphQL Detection
            if re.search(self.graphql_pattern, string):
                endpoint_findings["graphql"] = True

        # Convert set to list for JSON serialization
        endpoint_findings["urls"] = list(endpoint_findings["urls"])
        
        self.findings = endpoint_findings
        return self.findings
