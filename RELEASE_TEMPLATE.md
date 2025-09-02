
# Release Title: SecureCrypto-PythonBridge vX.Y.Z

## Summary
Short paragraph about what's new or important in this release.

## Changes
- Bullet points of notable changes (link to CHANGELOG)
  - e.g., Added: new helper `sign_file_to`
  - e.g., Fixed: improved error message in `init()`
  - e.g., Docs: expanded Implementation Ideas

## Assets
Attach or include the following files in the GitHub release:
- `SecureCrypto.dll`
- `securecrypto.py`
- `securecrypto_cheatsheet.pdf`
- `IMPLEMENTATION_IDEAS.md`
- `README.md`
- `CHANGELOG.md`

## Compatibility
- Python: 3.9+
- OS: Windows (CI validated)
- Dependencies: `pythonnet`

## Verification
1. Download assets listed above.
2. Ensure `SecureCrypto.dll` and `securecrypto.py` are in the same directory.
3. Run self-test:
   ```bash
   python securecrypto.py
   ```
4. Run examples:
   ```bash
   python examples/aes_example.py
   python examples/rsa_hybrid_example.py
   python examples/sign_verify_example.py
   ```

## Notes
- Keep private keys out of the repo and releases.
- For production usage, consider key management best practices and secrets storage.
