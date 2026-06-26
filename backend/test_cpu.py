import time
import asyncio

def read_cpu():
    with open("/proc/stat", "r") as f:
        line = f.readline()
    parts = line.split()
    times = [float(x) for x in parts[1:]]
    idle = times[3] + times[4]
    total = sum(times)
    return idle, total

async def test():
    for i in range(3):
        idle1, total1 = read_cpu()
        
        # Busy loop to consume CPU
        start = time.time()
        while time.time() - start < 0.2:
            _ = 123 * 456
            
        idle2, total2 = read_cpu()
        
        idle_diff = idle2 - idle1
        total_diff = total2 - total1
        pct = 0.0
        if total_diff > 0:
            pct = round((1.0 - idle_diff / total_diff) * 100, 1)
        print(f"Iteration {i}: idle_diff: {idle_diff}, total_diff: {total_diff}, percent: {pct}%")

asyncio.run(test())
