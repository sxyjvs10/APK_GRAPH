from abc import ABC, abstractmethod

class BaseIntelligenceModule(ABC):
    def __init__(self, apk_data):
        self.apk_data = apk_data
        self.findings = []

    @abstractmethod
    def analyze(self):
        """Perform analysis and populate self.findings."""
        pass

    def get_findings(self):
        return self.findings
