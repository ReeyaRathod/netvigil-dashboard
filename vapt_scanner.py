import socket
import concurrent.futures

# Predefined risk database for common network services
SERVICE_RISK_MAP = {
	21: {"service": "FTP", "risk": "High", "issue": "Unencrypted File Transfer", "recommendation": "Use SFTP/SSH instead of plaintext FTP."},
	22: {"service": "SSH", "risk": "Low", "issue": "Secure Shell Access", "recommendation": "Ensure key-based authentication is enforced and password authentication is disabled."},
	23: {"service": "Telnet", "risk": "Critical", "issue": "Cleartext Authentication", "recommendation": "Disable Telnet immediately and migrate to SSH."},
	80: {"service": "HTTP", "risk": "Medium", "issue": "Unencrypted Web Traffic", "recommendation": "Implement HTTPS using TLS/SSL certificates."},
	443: {"service": "HTTPS", "risk": "Low", "issue": "Encrypted Web Traffic", "recommendation": "Ensure modern TLS (v1.2/v1.3) protocols are enforced."},
	445: {"service": "SMB", "risk": "High", "issue": "File Sharing Service Exposed", "recommendation": "Disable SMBv1 and restrict port 445 access using firewall rules."},
	3389: {"service": "RDP", "risk": "High", "issue": "Remote Desktop Endpoint Exposed", "recommendation": "Enforce NLA (Network Level Authentication) and  restrict access via VPN."}
}

def scan_port(target_ip, port):
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.settimeout(0.5)
	result = sock.connect_ex((target_ip, port))
	sock.close()

	if result == 0:
		info = SERVICE_RISK_MAP.get(port, {
			"service": f"Unknown Port {port}",
			"risk": "Medium",
			"issue": f"Open TCP Port {port} detected",
			"recommendation": "Investigate service necessity and apply firewall filters."
		})
		return {
			"port": port,
			"service": info["service"],
			"risk": info["risk"],
			"issue": info["issue"],
			"recommendation": info["recommendation"]
		}
	return None

def run_vapt_scan(target_ip):
	# Standard common VAPT assessment ports
	common_ports = [21, 22, 23, 80, 443, 445, 3389, 8080, 8000]
	discovered = []

	with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
		futures = [executor.submit(scan_port, target_ip, port) for port in common_ports]
		for future in concurrent.futures.as_completed(futures):
			res = future.result()
			if res:
				discovered.append(res)

	# Sort by port number
	discovered.sort(key=lambda x: x["port"])

	# Calculte Risk Metrics
	risk_summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
	for d in discovered:
		risk_summary[d["risk"]] += 1

	return {
		"target": target_ip,
		"findings": discovered,
		"summary": risk_summary
	}

