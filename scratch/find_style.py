with open(r"c:\Users\cagri\honeypot-orchestrator\frontend\src\styles.css", "r", encoding="utf-8") as f:
    lines = f.readlines()

for idx, line in enumerate(lines):
    if "sidebar" in line.lower() or "nav-link" in line.lower():
        print(f"{idx+1}: {line.strip()}")
