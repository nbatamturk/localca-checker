# localca-checker

🔐 A local CLI tool to analyze certificate bundles (`.crt`) for security issues such as weak key size, SHA1, MD5, self-signing, expiry and more.

---

## 🚀 Features

- Analyzes `.crt` bundles with multiple certificates inside
- Extracts each certificate and checks:
  - Expiry
  - Key Size
  - SHA1 / MD5 usage
  - Self-Signed status
- Outputs detailed `result.txt` and `result_weak_only.txt`

---

## 🛠️ Installation

```bash
npm install -g localca-checker
```

## 📎 Usage

```bash
localca-checker ./your-cert-bundle.crt
```

---

## 📃 Example Output
```html
📜 Certificate #74 – QuoVadis Root CA 2
  Key Size            : FAILED - Insecure key (384 bits)
  SHA1                : WARNING - Using SHA1 (Deprecated)
  MD5                 : PASSED - Not using MD5
```
---
  
## 📜 License
MIT License. Use freely, contribute happily.

---
