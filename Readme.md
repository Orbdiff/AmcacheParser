# AmCacheParser

AmCacheParser is a forensic analysis tool designed to parse and analyze the **Amcache.hve** artifact. It offers detailed insights into executed binaries, including file paths, digital signature status, and Yara rule detections, all via an ImGui interface.

---

## Features

### Digital Signature Verification

* Verifies executables and categorizes them as:

  * **Signed**
  * **Unsigned**
  * **Not Found**

### Yara Rules Integration

* Includes a set of YARA rules to detect possible cheats or suspicious PE files.
* May produce false positives, so results should be manually validated.

### Advanced Filtering (Column-Based Search)

* Filtering system that works across **all visible columns**.
* Supports column-specific queries using the following syntax:

```
ColumnName:value;OtherColumn:value
```

**Examples:**

* `Signature:Signed`
* `Path:Steam;Signature:Unsigned`
* `Signature:Cheat;OS:false`

Notes:

* Filtering is **case-insensitive**.
* Multiple conditions can be combined using `;`.
* Only visible columns are considered during filtering.

### Quick Filters via Checkboxes

* Instantly narrow results using predefined checkboxes:

  * **Unsigned / Cheat**
  * **Instance entries only**
  * **NotFound**

### Extensible Columns

* Right-click the **last column header** to dynamically add more fields:

  * `IsOsComponent`
  * `LongPathHash`
  * `BinaryType`
  * `IsPE`

* Newly added columns are **automatically included** in the global and column-based search system.