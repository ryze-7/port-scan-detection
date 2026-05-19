import json

conn_log = "conn.log"
output_file = "conn_events.json"

# Read Zeek TSV
with open(conn_log) as f:
    lines = f.readlines()

# Extract field names from header
header_line = [l for l in lines if l.startswith("#fields")][0]
fields = header_line.replace("#fields", "").strip().split("\t")

# Parse data rows
events = []
for line in lines:
    if line.startswith("#") or not line.strip():
        continue  # Skip comment lines
    
    values = line.strip().split("\t")
    if len(values) != len(fields):
        continue  # Skip malformed lines
    
    record = dict(zip(fields, values))
    
    # Convert to JSON-friendly types
    event = {
        "timestamp": float(record["ts"]),
        "source_ip": record["id.orig_h"],
        "source_port": int(record["id.orig_p"]),
        "target_ip": record["id.resp_h"],
        "target_port": int(record["id.resp_p"]),
        "protocol": record["proto"],
        "service": record.get("service", "-"),
        "duration": float(record["duration"]),
        "bytes_sent": int(record["orig_bytes"]),
        "bytes_received": int(record["resp_bytes"]),
        "conn_state": record["conn_state"],
        "packets_sent": int(record["orig_pkts"]),
        "packets_received": int(record.get("resp_pkts", 0)),
        "ttl": int(record["orig_ip_ttl"]),
    }
    events.append(event)

# Write JSON lines (Splunk format)
with open(output_file, "w") as f:
    for event in events:
        f.write(json.dumps(event) + "\n")

print(f"✓ Converted {len(events)} connection events to JSON")
print(f"✓ Output: {output_file}")
