from apkgraph.core.engine import BaseIntelligenceModule
import re
import base64
import json

class JWTAnalyzer(BaseIntelligenceModule):
    def __init__(self, apk_data):
        super().__init__(apk_data)
        self.jwt_pattern = r"ey[A-Za-z0-9-_=]+\.ey[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*"

    def analyze(self):
        analysis = self.apk_data['analysis']
        jwt_findings = []

        for string_analysis in analysis.get_strings():
            string = string_analysis.get_value()
            matches = re.findall(self.jwt_pattern, string)
            for match in matches:
                try:
                    # Try to decode JWT header/payload
                    parts = match.split('.')
                    if len(parts) >= 2:
                        header = self._decode_base64(parts[0])
                        payload = self._decode_base64(parts[1])
                        
                        jwt_findings.append({
                            "token": match,
                            "header": header,
                            "payload": payload
                        })
                except:
                    continue

        self.findings = jwt_findings
        return self.findings

    def _decode_base64(self, data):
        try:
            missing_padding = len(data) % 4
            if missing_padding:
                data += '=' * (4 - missing_padding)
            decoded = base64.b64decode(data).decode('utf-8')
            return json.loads(decoded)
        except:
            return None
