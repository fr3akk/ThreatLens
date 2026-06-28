class BaseThreatConnector:
    name: str = ""
    def lookup(self, ioc: str, ioc_type: str):
        raise NotImplementedError("This method should be implemented by subclasses.")