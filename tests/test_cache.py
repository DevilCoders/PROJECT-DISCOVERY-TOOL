from pathlib import Path
from project_discovery.cache import ScanCache

def test_cache_roundtrip(tmp_path: Path):
    path = tmp_path/"cache.sqlite3"
    with ScanCache(path) as cache:
        assert cache.get("/repo","a.py") is None
        cache.put("/repo","a.py",10,20,"abc")
    with ScanCache(path) as cache:
        assert cache.get("/repo","a.py") == (10,20,"abc")
