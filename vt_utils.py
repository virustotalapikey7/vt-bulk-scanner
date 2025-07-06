import requests

# 🔐 Replace with your actual API key
API_KEY = "c3c9a19d9a762d87f5f944990d874013160de4a5f45516f8d30989630f964329"

HEADERS = {
    "x-apikey": API_KEY
}

def check_hashes(hashes):
    results = []
    for file_hash in hashes:
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        response = requests.get(url, headers=HEADERS)
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            result = {
                "id": file_hash,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0)
            }
        else:
            result = {
                "id": file_hash,
                "error": f"Error {response.status_code}"
            }
        results.append(result)
    return results


def check_ips(ips):
    results = []
    for ip in ips:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        response = requests.get(url, headers=HEADERS)
        if response.status_code == 200:
            data = response.json()
            attr = data["data"]["attributes"]

            result = {
                "id": ip,
                "reputation": attr.get("reputation", "N/A"),
                "country": attr.get("country", "N/A"),
                "city": attr.get("city", "N/A"),
                "asn": attr.get("asn", "N/A"),
                "domain": attr.get("last_https_certificate", {}).get("subject", {}).get("CN", "N/A"),
                "malicious": attr["last_analysis_stats"].get("malicious", 0),
                "suspicious": attr["last_analysis_stats"].get("suspicious", 0)
            }
        else:
            result = {
                "id": ip,
                "error": f"Error {response.status_code}"
            }

        results.append(result)
    return results
