from backend.connectors.virustotal import VirusTotalConnector

connector = VirusTotalConnector()

result = connector.lookup("8.8.8.8", "ipv4")

print(result)