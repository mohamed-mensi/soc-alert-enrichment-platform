from database.db_manager import DBManager

db = DBManager()

ips = [
    "31.172.83.162",
    "159.100.14.254", 
    "185.236.232.20",
    "91.142.74.28",
]

hashes = [
    "b4ad5df385ee964fe9a800f2cdaa03626c8e8811ddb171f8e821876373335e63",
    "d8b2d883d3b376833fa8e2093e82d0a118ba13b01a2054f8447f57d9fec67030",
]

print("=== Verification ===")
for ip in ips:
    r = db.lookup_ioc("ip", ip)
    if r:
        print(f"  ✅ {ip:20} → {r[0]['malware_family']} ({r[0]['source']})")
    else:
        print(f"  ❌ {ip:20} → not found")

for h in hashes:
    r = db.lookup_ioc("hash", h)
    if r:
        print(f"  ✅ {h[:25]}... → {r[0]['malware_family']} ({r[0]['source']})")
    else:
        print(f"  ❌ {h[:25]}... → not found")

print(f"\nTotal IOCs: {db.get_ioc_count()}")