"""
Generate sample test PCAP files for the not_trained folder
These are different samples not used in training
"""

import json
import random
import sys
from datetime import datetime

# Fix Windows Unicode encoding
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# Set seed for reproducibility
random.seed(43)  # Different seed than training (42)

def generate_test_normal_traffic():
    """Generate normal network traffic samples"""
    normal_flows = []

    for i in range(75):  # 75 normal flows for testing
        flow = {
            "flow_id": f"test_normal_{i:04d}",
            "src_ip": f"192.168.1.{random.randint(1, 254)}",
            "dst_ip": f"10.0.0.{random.randint(1, 254)}",
            "src_port": random.randint(50000, 65535),
            "dst_port": random.choice([80, 443, 22, 21, 25, 53, 123]),
            "protocol": random.choice(["TCP", "UDP"]),
            "duration": round(random.uniform(0.5, 30), 2),
            "packets": random.randint(5, 500),
            "bytes": random.randint(500, 100000),
            "label": 0  # Normal
        }
        normal_flows.append(flow)

    return normal_flows

def generate_test_attack_traffic():
    """Generate attack/suspicious network traffic samples"""
    attack_flows = []

    for i in range(75):  # 75 attack flows for testing
        flow = {
            "flow_id": f"test_attack_{i:04d}",
            "src_ip": f"203.0.113.{random.randint(1, 254)}",  # Different subnet
            "dst_ip": f"192.168.1.100",
            "src_port": random.randint(10000, 50000),
            "dst_port": random.choice([22, 23, 3389, 445, 139]),  # Common attack ports
            "protocol": "TCP",
            "duration": round(random.uniform(0.1, 5), 2),  # Shorter duration
            "packets": random.randint(50, 10000),  # More packets
            "bytes": random.randint(50000, 5000000),  # Much larger
            "label": 1  # Attack/Suspicious
        }
        attack_flows.append(flow)

    return attack_flows

def save_to_csv(flows, filename):
    """Save flows to CSV format"""
    import csv
    with open(filename, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=flows[0].keys())
        writer.writeheader()
        writer.writerows(flows)
    print(f"✓ {filename} created ({len(flows)} samples)")

def main():
    print("\n[TEST DATA] Generating test samples for not_trained/ folder...\n")

    # Generate normal traffic
    normal_flows = generate_test_normal_traffic()
    save_to_csv(normal_flows, "test_normal_traffic.csv")

    # Generate attack traffic
    attack_flows = generate_test_attack_traffic()
    save_to_csv(attack_flows, "test_attack_traffic.csv")

    # Generate mixed traffic
    mixed_flows = normal_flows + attack_flows
    random.shuffle(mixed_flows)
    save_to_csv(mixed_flows, "test_mixed_traffic.csv")

    # Save metadata
    metadata = {
        "description": "Test dataset - NOT used in training",
        "created": datetime.now().isoformat(),
        "normal_samples": len(normal_flows),
        "attack_samples": len(attack_flows),
        "total_samples": len(normal_flows) + len(attack_flows),
        "purpose": "Evaluate model on unseen data"
    }

    with open("test_metadata.json", "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"✓ test_metadata.json created")

    print(f"\n[SUCCESS] Test data generation complete!")
    print(f"  - test_normal_traffic.csv    (75 normal samples)")
    print(f"  - test_attack_traffic.csv    (75 attack samples)")
    print(f"  - test_mixed_traffic.csv     (150 mixed samples)")
    print(f"  - test_metadata.json         (metadata)")
    print(f"\nReady for model evaluation!\n")

if __name__ == "__main__":
    main()
