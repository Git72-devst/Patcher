from __future__ import annotations

import datetime as _dt
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERSION = "5.8.0.74"
ARCHIVE = ROOT / "github-server" / "archives" / f"{VERSION}.zip"
INDEX = ROOT / "github-server" / "index.json"
MANIFEST = ROOT / "github-server" / "manifest.json"


def main() -> None:
    data = ARCHIVE.read_bytes()
    sha256 = hashlib.sha256(data).hexdigest()
    size = len(data)
    updated_at = _dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

    index = json.loads(INDEX.read_text(encoding="utf-8-sig"))
    index["updatedAt"] = updated_at
    for item in index["versions"]:
        if item["version"] == VERSION:
            item["sha256"] = sha256
            item["size"] = size
            break
    else:
        raise RuntimeError(f"{VERSION} is missing in index.json")
    INDEX.write_text(json.dumps(index, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8-sig"))
    manifest["updatedAt"] = updated_at
    manifest["versions"][VERSION]["sha256"] = sha256
    manifest["versions"][VERSION]["size"] = size
    MANIFEST.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(sha256)
    print(size)


if __name__ == "__main__":
    main()
