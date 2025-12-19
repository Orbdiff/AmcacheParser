# AmCacheParser

**AmcacheParser** is a tool for analyzing a forensic artifact, specifically `Amcache.hve`, it provides file paths, digital signatures, and Yara rules.

---

## Features

- **AmCache.hve Parser**: Parses `Amcache.hve` using [Eric Zimmerman's AmcacheParser](https://github.com/EricZimmerman/AmcacheParser).
- **Digital Signature Verification**: Identifies whether executables are signed, unsigned, or not found.
- **Yara Rules**: Includes certain Yara rules to detect possible cheats (may, of course, produce false positives)

## TODO

- [ ] Add a GUI
