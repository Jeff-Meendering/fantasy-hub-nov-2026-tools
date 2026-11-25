# Fantasy Hub (Nov 2026) Tools

Offline static analysis tools for `До_Вылета.apk` (`96cf6822cc7f421cd10cd9ca463b1f04b54929e6b1949743a56531b13d6479ee`). Nothing here runs the sample or touches the network.

- `extract_config.py` unpacks Stages 2 and 3 from the Stage 1 APK, decodes the native Caesar and StringFog strings, and prints JSON (redacts the Telegram token unless `--show-secrets` is passed; AArch64 only for native parsing).
- `fh_c2crypto.py` decodes (or encodes with `--encrypt`) outgoing WebSocket `{"p": "..."}` frames using JNI modified UTF-8.
- `do_vyleta_fantasyhub.yar` has 7 YARA rules covering Stage 1, the Stage 2 template, all three native libs, `stage3.dex`, and a loose hunting rule for `libreality_transport.so`.

Usage...

```text
python3 extract_config.py <stage1.apk> > config.json
python3 fh_c2crypto.py '{"p":"..."}'
python3 fh_c2crypto.py --encrypt '{"action":"test"}'
yara -w do_vyleta_fantasyhub.yar <file>
```

Only tested on this sample plus a small goodware check (~100k Ubuntu `/usr` files and 204 F-Droid APKs, 0 hits), so test before using the YARA rules in production.
