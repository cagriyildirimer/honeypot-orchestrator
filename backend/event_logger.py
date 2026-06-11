from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class JSONLEventLogger:
    def __init__(self, path: Path) -> None:
        self.path = path
        # Ayni anda gelen baglanti olaylarinin dosyaya karismadan yazilmasi icin kilit.
        self._lock = asyncio.Lock()

    async def log(self, event: dict[str, Any]) -> None:
        # Log klasoru yoksa ilk olay yazilirken olusturulur.
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Her olaya okunabilir bir UTC zaman damgasi eklenir; gelen alanlar bunun yanina eklenir.
        record = {
            "timestamp": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
            **event,
        }
        # JSONL formati: her satir ayri bir JSON kaydidir.
        line = json.dumps(record, ensure_ascii=True, sort_keys=True)
        async with self._lock:
            # Dosya yazma islemi bloklayici oldugu icin ayri thread'e alinir.
            await asyncio.to_thread(self._append_line, line)

    def _append_line(self, line: str) -> None:
        # Check size for rotation (50MB)
        if self.path.exists() and self.path.stat().st_size > 50 * 1024 * 1024:
            self._rotate()
        # append modu eski kayitlari korur ve yeni olayi dosyanin sonuna ekler.
        with self.path.open("a", encoding="utf-8") as file:
            file.write(line + "\n")

    def _rotate(self) -> None:
        try:
            for i in range(4, 0, -1):
                old = Path(str(self.path) + f".{i}")
                new = Path(str(self.path) + f".{i+1}")
                if old.exists():
                    old.replace(new)
            self.path.replace(Path(str(self.path) + ".1"))
        except Exception:
            pass
