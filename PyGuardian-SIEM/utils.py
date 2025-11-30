def is_port_scan(src_ip, dst_port, record):
    if src_ip not in record:
        record[src_ip] = set()

    record[src_ip].add(dst_port)

    # More than 10 unique ports = port scan
    return len(record[src_ip]) > 10


def is_ddos(src_ip, counter):
    counter[src_ip] = counter.get(src_ip, 0) + 1

    # More than 50 packets = DDoS pattern
    return counter[src_ip] > 50


def suspicious_dns(domain):
    bad_keywords = ["malware", "phishing", "botnet", "stealer", "spyware"]

    return any(word in domain.lower() for word in bad_keywords)
