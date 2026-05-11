from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class JSONLEventLogger:
    def __init__(self, path: Path) -> None:
        self.path = path
        # Aynı anda gelen bağlantı olaylarının dosyaya karışmadan yazılması için kilit.
        self._lock = asyncio.Lock()

    async def log(self, event: dict[str, Any]) -> None:
        # Log klasörü yoksa ilk olay yazılırken oluşturulur.
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Her olaya UTC zaman damgası eklenir; gelen alanlar bunun yanına eklenir.
        record = {
            "timestamp": datetime.now(UTC).isoformat(),
            **event,
        }
        # JSONL formatı: her satır ayrı bir JSON kaydıdır.
        line = json.dumps(record, ensure_ascii=True, sort_keys=True)
        async with self._lock:
            # Dosya yazma işlemi bloklayıcı olduğu için ayrı thread'e alınır.
            await asyncio.to_thread(self._append_line, line)

    def _append_line(self, line: str) -> None:
        # append modu eski kayıtları korur ve yeni olayı dosyanın sonuna ekler.
        with self.path.open("a", encoding="utf-8") as file:
            file.write(line + "\n")
