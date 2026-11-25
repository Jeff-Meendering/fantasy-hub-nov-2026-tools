#!/usr/bin/env python3
"""Offline static config extractor for До_Вылета.apk (Fantasy Hub, Nov 2026)."""

import argparse
import base64
import hashlib
import json
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path

TOOL_VERSION = "2.2"

STAGE1_ASSET_MAGIC = b"\xc9\x3b\x7a\x4f"
KNOWN_KEYS = {
    "96cf6822cc7f421cd10cd9ca463b1f04b54929e6b1949743a56531b13d6479ee":
        "423b1d49715525d46673f21d8b4d2b8fd9246505f384defec20a86159fbedf65",
}

MAX_ENTRY_SIZE = 128 * 1024 * 1024
MAX_STAGE_SIZE = 256 * 1024 * 1024

DOMAIN_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{2,60}\.[a-z]{2,12}$")
HOSTNAME_RE = re.compile(r"(?:[a-z0-9-]{1,63}\.)+[a-z]{2,12}")
B64_RE = re.compile(r"[A-Za-z0-9+/]+={0,2}")
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def defang(value: str) -> str:
    out = value.replace("https://", "hxxps://").replace("http://", "hxxp://")
    out = out.replace("wss://", "wss[:]//").replace("ws://", "ws[:]//")
    return out.replace(".", "[.]")


def hashes_of(data: bytes) -> dict:
    return {
        "size": len(data),
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def xor_repeat(data: bytes, key: bytes) -> bytes:
    if not data:
        return b""
    if not key:
        raise ValueError("empty XOR key")
    n = len(data)
    stream = (key * (n // len(key) + 1))[:n]
    return (int.from_bytes(data, "little") ^ int.from_bytes(stream, "little")).to_bytes(n, "little")


def inflate_limited(data: bytes, wbits: int, limit: int) -> bytes:
    d = zlib.decompressobj(wbits)
    out = d.decompress(data, limit)
    if d.unconsumed_tail:
        raise ValueError(f"decompressed size exceeds limit of {limit} bytes")
    if not d.eof:
        raise ValueError("compressed stream is truncated")
    return out


def is_printable_ascii(b: bytes) -> bool:
    return bool(b) and all(0x20 <= c <= 0x7E for c in b)


def _find_eocd(data: bytes) -> tuple[int, int, int]:
    min_pos = max(0, len(data) - 65557)
    pos = len(data)
    fallback = None
    while True:
        eocd = data.rfind(b"PK\x05\x06", min_pos, pos)
        if eocd == -1:
            break
        pos = eocd
        if eocd + 22 > len(data):
            continue
        _, _, _, _, total_entries, cd_size, cd_offset, comment_len = struct.unpack_from("<IHHHHIIH", data, eocd)
        if eocd + 22 + comment_len == len(data):
            return eocd, total_entries, cd_offset
        if fallback is None and cd_offset + cd_size <= eocd and data[cd_offset : cd_offset + 4] == b"PK\x01\x02":
            fallback = (eocd, total_entries, cd_offset)
    if fallback is not None:
        return fallback
    raise ValueError("ZIP End of Central Directory not found")


def read_zip_entries_raw(data: bytes) -> list[dict]:
    _eocd, total_entries, cd_offset = _find_eocd(data)
    if total_entries == 0xFFFF or cd_offset == 0xFFFFFFFF:
        raise ValueError("ZIP64 archives are not supported")
    pos = cd_offset
    entries = []
    for _ in range(total_entries):
        if pos + 46 > len(data):
            break
        (sig, _vm, _vn, flags, method, _mt, _md, crc, csize, usize,
         fnlen, exlen, cmlen, _disk, _ia, _ea, lh_off) = struct.unpack_from("<IHHHHHHIIIHHHHHII", data, pos)
        if sig != 0x02014B50:
            break
        name = data[pos + 46 : pos + 46 + fnlen].decode("utf-8", errors="replace")
        pos += 46 + fnlen + exlen + cmlen

        lflags = lmethod = None
        content = None
        if lh_off + 30 <= len(data):
            lsig, _lver, lflags_v, lmethod_v, _lt, _ld, _lcrc, _lcs, _lus, lfnlen, lexlen = struct.unpack_from(
                "<IHHHHHIIIHH", data, lh_off
            )
            if lsig == 0x04034B50:
                lflags, lmethod = lflags_v, lmethod_v
                start = lh_off + 30 + lfnlen + lexlen
                comp = data[start : start + csize]
                try:
                    if method == 0:
                        content = comp if len(comp) <= MAX_ENTRY_SIZE else None
                    elif method == 8:
                        content = inflate_limited(comp, -15, MAX_ENTRY_SIZE)
                except (zlib.error, ValueError):
                    content = None
        entries.append({
            "name": name, "flags": flags, "lflags": lflags, "method": method, "lmethod": lmethod,
            "csize": csize, "usize": usize, "crc": crc, "content": content,
        })
    return entries


def zip_anomalies(entries: list[dict]) -> dict:
    shadow_roots = ("AndroidManifest.xml/", "classes.dex/", "resources.arsc/")
    return {
        "total_zip_entries": len(entries),
        "zero_byte_assets": sum(1 for e in entries if e["name"].startswith("assets/") and e["usize"] == 0),
        "fake_encrypted_entries": [
            {"name": e["name"], "central_flags": hex(e["flags"]),
             "local_flags": hex(e["lflags"]) if e["lflags"] is not None else None}
            for e in entries
            if (e["flags"] & 1) or (e["lflags"] is not None and e["lflags"] & 1)
        ],
        "method_mismatch_entries": [
            e["name"] for e in entries if e["lmethod"] is not None and e["lmethod"] != e["method"]
        ],
        "shadow_path_entries": [
            e["name"] for e in entries
            if e["name"].startswith("/") or e["name"].startswith(shadow_roots)
            or e["name"] in ("META-INF/AndroidManifest.xml", "META-INF/classes.dex")
        ],
    }


def extract_apk_sig_block_certs(apk: bytes) -> list[dict]:
    magic = b"APK Sig Block 42"
    try:
        _eocd, _total, cd_offset = _find_eocd(apk)
    except ValueError:
        return []
    idx = cd_offset - len(magic)
    if idx < 8 or apk[idx:cd_offset] != magic:
        return []
    size_of_block = struct.unpack_from("<Q", apk, idx - 8)[0]
    block_start = cd_offset - size_of_block - 8
    if block_start < 0 or block_start + 8 > idx - 8:
        raise ValueError("APK Signing Block size field is out of range")
    head_size = struct.unpack_from("<Q", apk, block_start)[0]
    if head_size != size_of_block:
        raise ValueError("APK Signing Block header/footer size mismatch")
    pos, end = block_start + 8, idx - 8
    scheme_names = {0x7109871A: "v2", 0xF05368C0: "v3", 0x1B93AD61: "v3.1"}
    openssl = shutil.which("openssl")
    certs: dict[str, dict] = {}

    while pos + 12 <= end:
        pair_len = struct.unpack_from("<Q", apk, pos)[0]
        if pair_len < 4 or pos + 8 + pair_len > end:
            break
        pair_id = struct.unpack_from("<I", apk, pos + 8)[0]
        val = apk[pos + 12 : pos + 8 + pair_len]
        pos += 8 + pair_len
        if pair_id not in scheme_names:
            continue
        off = 4
        signers_end = 4 + struct.unpack_from("<I", val, 0)[0]
        while off + 4 <= min(signers_end, len(val)):
            signer_len = struct.unpack_from("<I", val, off)[0]
            signer = val[off + 4 : off + 4 + signer_len]
            off += 4 + signer_len
            sd = signer[4 : 4 + struct.unpack_from("<I", signer, 0)[0]]
            sdo = 4 + struct.unpack_from("<I", sd, 0)[0]  # skip digests
            certs_end = sdo + 4 + struct.unpack_from("<I", sd, sdo)[0]
            sdo += 4
            while sdo + 4 <= min(certs_end, len(sd)):
                c_len = struct.unpack_from("<I", sd, sdo)[0]
                der = sd[sdo + 4 : sdo + 4 + c_len]
                sdo += 4 + c_len
                h = hashlib.sha256(der).hexdigest()
                if h not in certs:
                    info = {"schemes": [], "der_size": len(der), "sha256": h,
                            "sha1": hashlib.sha1(der).hexdigest(), "md5": hashlib.md5(der).hexdigest()}
                    if openssl:
                        info.update(_openssl_describe(openssl, der))
                    certs[h] = info
                if scheme_names[pair_id] not in certs[h]["schemes"]:
                    certs[h]["schemes"].append(scheme_names[pair_id])
    return list(certs.values())


def _openssl_describe(openssl: str, der: bytes) -> dict:
    try:
        with tempfile.NamedTemporaryFile(suffix=".der") as tf:
            tf.write(der)
            tf.flush()
            out = subprocess.check_output(
                [openssl, "x509", "-inform", "DER", "-in", tf.name, "-noout",
                 "-subject", "-issuer", "-serial", "-dates"],
                stderr=subprocess.DEVNULL, timeout=10,
            ).decode("utf-8", errors="replace")
    except (OSError, subprocess.SubprocessError):
        return {}
    info = {}
    for ln in out.splitlines():
        if "=" in ln:
            k, v = ln.split("=", 1)
            info[k.strip()] = v.strip()
    return info


def find_stage1_key32_in_dex(dex: bytes, payload: bytes) -> bytes | None:
    if not payload.startswith(STAGE1_ASSET_MAGIC) or len(payload) < 8 + 64:
        return None
    prefix = xor_repeat(payload[8 : 8 + 512], payload[4:8])
    marker = struct.pack("<HHI", 0x0300, 1, 32)  # fill-array-data, width 1, 32 bytes
    pos = 0
    while True:
        idx = dex.find(marker, pos)
        if idx == -1:
            return None
        pos = idx + 2
        cand = dex[idx + 8 : idx + 40]
        if len(cand) != 32:
            continue
        b0, b1 = prefix[0] ^ cand[0], prefix[1] ^ cand[1]
        if b0 != 0x78 or (b0 * 256 + b1) % 31:
            continue
        try:
            if zlib.decompressobj().decompress(xor_repeat(prefix, cand), 16).startswith(b"PK\x03\x04"):
                return cand
        except zlib.error:
            continue


def decrypt_stage1_asset(blob: bytes, key32: bytes | None) -> tuple[bytes, bytes]:
    if not blob.startswith(STAGE1_ASSET_MAGIC) or len(blob) < 8:
        raise ValueError("asset does not start with magic c93b7a4f")
    key4 = blob[4:8]
    out = xor_repeat(blob[8:], key4)
    if key32 is not None:
        out = xor_repeat(out, key32)
    return key4, out


def elf64_load_segments(so: bytes) -> list[tuple[int, int, int, int]]:
    if so[:4] != b"\x7fELF" or so[4] != 2 or so[5] != 1:
        raise ValueError("not a little-endian ELF64 file")
    e_phoff = struct.unpack_from("<Q", so, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", so, 0x36)
    segs = []
    for i in range(e_phnum):
        p_type, p_flags, p_off, p_va, _, p_filesz, _, _ = struct.unpack_from("<IIQQQQQQ", so, e_phoff + i * e_phentsize)
        if p_type == 1:
            segs.append((p_va, p_filesz, p_off, p_flags))
    return segs


def elf_machine(so: bytes) -> int:
    return struct.unpack_from("<H", so, 0x12)[0] if len(so) > 0x14 else 0


def elf64_dynsym_functions(so: bytes) -> list[tuple[int, int, str]]:
    try:
        e_shoff = struct.unpack_from("<Q", so, 0x28)[0]
        e_shentsize, e_shnum = struct.unpack_from("<HH", so, 0x3A)
        sections = [struct.unpack_from("<IIQQQQIIQQ", so, e_shoff + i * e_shentsize) for i in range(e_shnum)]
    except struct.error:
        return []
    out = []
    for sec in sections:
        if sec[1] != 11 or sec[6] >= len(sections):  # SHT_DYNSYM
            continue
        str_off, str_size = sections[sec[6]][4], sections[sec[6]][5]
        strtab = so[str_off : str_off + str_size]
        for off in range(sec[4], sec[4] + sec[5] - 23, 24):
            st_name, st_info, _, st_shndx, st_value, st_size = struct.unpack_from("<IBBHQQ", so, off)
            if st_shndx == 0 or (st_info & 0xF) != 2:  # STT_FUNC
                continue
            end = strtab.find(b"\x00", st_name)
            if end != -1:
                out.append((st_value, st_size, strtab[st_name:end].decode("ascii", errors="replace")))
    return sorted(out)


def _va_to_off(segs, va: int) -> int | None:
    for s_va, s_sz, s_off, _ in segs:
        if s_va <= va < s_va + s_sz:
            return s_off + (va - s_va)
    return None


def _bl_callsites(so: bytes, segs) -> dict[int, list[int]]:
    targets: dict[int, list[int]] = {}
    for s_va, s_sz, s_off, s_flags in segs:
        if not s_flags & 1:
            continue
        for o in range(0, s_sz - 3, 4):
            insn = struct.unpack_from("<I", so, s_off + o)[0]
            if (insn & 0xFC000000) != 0x94000000:
                continue
            imm = insn & 0x03FFFFFF
            if imm & 0x02000000:
                imm -= 0x04000000
            targets.setdefault(s_va + o + (imm << 2), []).append(s_va + o)
    return targets


def _recover_call_args(so: bytes, segs, pc: int) -> tuple[int, int, int] | None:
    x0 = w1 = w2 = None
    pending_add: tuple[int, int] | None = None
    for back in range(1, 25):
        off = _va_to_off(segs, pc - 4 * back)
        if off is None:
            break
        iw = struct.unpack_from("<I", so, off)[0]
        rd = iw & 0x1F
        cur_pc = pc - 4 * back
        if (iw & 0xFC000000) in (0x94000000, 0x14000000):  # BL / B
            break
        if (iw & 0xFFFFFC1F) in (0xD63F0000, 0xD61F0000, 0xD65F0000):  # BLR / BR / RET
            break
        if x0 is None:
            if pending_add is None and rd == 0:
                if (iw & 0x9F000000) == 0x10000000:  # ADR
                    imm = (((iw >> 5) & 0x7FFFF) << 2) | ((iw >> 29) & 3)
                    if imm & (1 << 20):
                        imm -= 1 << 21
                    x0 = cur_pc + imm
                elif (iw & 0xFF800000) == 0x91000000:  # ADD imm
                    rn = (iw >> 5) & 0x1F
                    imm12 = (iw >> 10) & 0xFFF
                    sh = (iw >> 22) & 1
                    pending_add = (rn, imm12 << (12 if sh else 0))
            elif pending_add is not None and rd == pending_add[0]:
                if (iw & 0x9F000000) == 0x90000000:  # ADRP
                    imm = ((((iw >> 5) & 0x7FFFF) << 2) | ((iw >> 29) & 3)) << 12
                    if imm & (1 << 32):
                        imm -= 1 << 33
                    x0 = (cur_pc & ~0xFFF) + imm + pending_add[1]
        if (iw & 0x7FE00000) == 0x52800000:  # MOVZ
            if rd == 1 and w1 is None:
                w1 = (iw >> 5) & 0xFFFF
            elif rd == 2 and w2 is None:
                w2 = (iw >> 5) & 0xFFFF
        if x0 is not None and w1 is not None and w2 is not None:
            return x0, w1, w2
    return None


def decode_caesar_callsites(so: bytes) -> dict:
    if elf_machine(so) != 183:
        raise ValueError("Caesar scan supports AArch64 only")
    segs = elf64_load_segments(so)
    callers_of = _bl_callsites(so, segs)

    best: dict = {"helper_va": None, "strings": [], "unresolved_callsites": 0}
    for s_va, s_sz, s_off, s_flags in segs:
        if not s_flags & 1:
            continue
        for o in range(0, s_sz - 7, 4):
            i0, i1 = struct.unpack_from("<II", so, s_off + o)
            if (i0 & 0xFFE0FC00) != 0x4B000000:  # sub wA, wB, wC
                continue
            if (i1 & 0xFFE00C00) != 0x38200800 or (i1 & 0x1F) != (i0 & 0x1F):  # strb wA, [xD, xE]
                continue
            for back in range(1, 65):
                if o - 4 * back < 0:
                    break
                start_va = s_va + o - 4 * back
                pw = struct.unpack_from("<I", so, s_off + o - 4 * back)[0]
                is_prologue = (pw & 0xFFC07FFF) == 0xA9807BFD or (pw & 0xFF8003FF) == 0xD10003FF
                if not is_prologue or start_va not in callers_of:
                    continue
                strings, unresolved = [], 0
                for pc in sorted(callers_of[start_va]):
                    args = _recover_call_args(so, segs, pc)
                    raw = None
                    if args and 1 <= args[1] <= 1024:
                        d_off = _va_to_off(segs, args[0])
                        if d_off is not None:
                            raw = bytes((b - args[2]) & 0xFF for b in so[d_off : d_off + args[1]])
                    if raw is not None and is_printable_ascii(raw):
                        strings.append({"pc": pc, "shift": args[2], "encoded_va": args[0], "value": raw.decode("ascii")})
                    else:
                        unresolved += 1
                if len(strings) > len(best["strings"]):
                    best = {"helper_va": start_va, "strings": strings, "unresolved_callsites": unresolved}
    return best


def _off_to_va(segs, off: int) -> int | None:
    for s_va, s_sz, s_off, _ in segs:
        if s_off <= off < s_off + s_sz:
            return s_va + (off - s_off)
    return None


def iter_stage2_loader_params(so: bytes, asset_names: set[str]):
    try:
        segs = elf64_load_segments(so)
    except ValueError:
        segs = None
    limit = min(len(so), 1 << 20)
    for off in range(0, limit - 36, 4):
        table_va = _off_to_va(segs, off) if segs else None
        paths = []
        cur = off
        while cur + 4 <= limit and len(paths) < 16:
            rel = struct.unpack_from("<i", so, cur)[0]
            if rel == 0:
                break
            if segs and table_va is not None:
                p = _va_to_off(segs, table_va + rel)
                if p is None or not (0 <= p < limit):
                    break
            else:
                p = off + rel
                if not (0 <= p < limit):
                    break
            end = so.find(b"\x00", p, p + 160)
            if end == -1 or end == p:
                break
            try:
                s = so[p:end].decode("ascii")
            except UnicodeDecodeError:
                break
            if f"assets/{s}" not in asset_names:
                break
            paths.append(s)
            cur += 4
        if paths and len(set(paths)) == len(paths) and cur + 32 <= len(so):
            yield paths, so[cur : cur + 32]


def extract_stage2_loader_params(
    so: bytes, asset_names: set[str], s2_files: dict[str, bytes] | None = None
) -> tuple[list[str], bytes]:
    for paths, key32 in iter_stage2_loader_params(so, asset_names):
        if s2_files is None:
            return paths, key32
        try:
            joined = b"".join(s2_files[f"assets/{p}"] for p in paths)
            prefix = xor_repeat(joined[:512], key32)
            if zlib.decompressobj(47).decompress(prefix, 8).startswith(b"dex\n"):
                return paths, key32
        except (KeyError, zlib.error, ValueError):
            continue
    raise ValueError("shard table / XOR key not found in native loader")


def jni_exports(so: bytes) -> list[dict]:
    out = []
    for _, _, name in elf64_dynsym_functions(so):
        if not name.startswith("Java_"):
            continue
        parts = re.split(r"_(?!\d)", name[5:])
        parts = [p.replace("_1", "_") for p in parts]
        if len(parts) >= 2:
            out.append({"symbol": name, "class": "/".join(parts[:-1]), "method": parts[-1]})
    return out


def interpret_native_config(decoded: dict, so: bytes, dex_blobs: list[bytes], b64_candidates: list[str]) -> dict:
    funcs = [(v, s, n) for v, s, n in elf64_dynsym_functions(so) if s]

    def owner(pc: int) -> str | None:
        for v, s, n in funcs:
            if v <= pc < v + s:
                return n
        return None

    groups: dict[str | None, list[str]] = {}
    for item in decoded["strings"]:
        groups.setdefault(owner(item["pc"]), []).append(item["value"])

    result: dict = {
        "decoder_va": hex(decoded["helper_va"]) if decoded["helper_va"] is not None else None,
        "decoded_strings": [
            {"pc": hex(i["pc"]), "shift": i["shift"], "function": owner(i["pc"]), "value": i["value"]}
            for i in decoded["strings"]
        ],
        "unresolved_callsites": decoded["unresolved_callsites"],
        "shifts_seen": sorted({i["shift"] for i in decoded["strings"]}),
    }

    telegram: dict = {}
    for fn, vals in groups.items():
        if fn is None or not fn.startswith("Java_"):
            continue
        joined = "".join(vals)
        if re.fullmatch(r"\d{6,12}:[A-Za-z0-9_-]{30,40}", joined):
            telegram["bot_token"], telegram["bot_token_getter"] = joined, fn
        elif re.fullmatch(r"-?\d{6,15}", joined):
            telegram["chat_id"], telegram["chat_id_getter"] = joined, fn
        elif joined.startswith(("http://", "https://")):
            telegram["gate_url"], telegram["gate_url_getter"] = joined, fn
    if telegram:
        getters = [v for k, v in telegram.items() if k.endswith("_getter")]
        classes = {e["class"] for e in jni_exports(so) if e["symbol"] in getters}
        telegram["getter_class_present_in_dex"] = any(
            (b"L" + c.encode() + b";") in blob for c in classes for blob in dex_blobs
        )
        result["telegram"] = telegram

    internal = groups.get(None, []) + [
        v for fn, vals in groups.items() if fn is not None and not fn.startswith("Java_") for v in vals
    ]
    counts: dict[str, int] = {}
    for v in internal:
        counts[v] = counts.get(v, 0) + 1

    for v in counts:
        if re.fullmatch(r"[a-z]+(/[A-Za-z0-9_$]+){2,}", v) and any(
            (b"L" + v.encode() + b";") in blob for blob in dex_blobs
        ):
            result["jni_config_class"] = v

    best_key, best_hits = None, 0
    for v in counts:
        hits = len(decode_b64_xor_domains(b64_candidates, v))
        if hits > best_hits:
            best_key, best_hits = v, hits
    if best_key:
        result["domain_b64_xor_key"] = best_key

    repeated = [v for v, c in counts.items() if c >= 2 and v != best_key]
    numeric = [v for v in counts if re.fullmatch(r"\d{4,12}", v)]
    version = [v for v in counts if re.fullmatch(r"v\d{1,4}", v)]
    if len(numeric) == 1:
        result["bot_id_prefix"] = numeric[0]
    if len(version) == 1:
        result["bot_id_suffix"] = version[0]
    if len(repeated) == 1:
        result["c2_payload_key_inferred"] = repeated[0]
    elif not repeated:
        used = {best_key, result.get("jni_config_class"), result.get("bot_id_prefix"), result.get("bot_id_suffix")}
        leftover = [v for v in counts if v not in used and len(v) >= 8]
        if len(leftover) == 1:
            result["c2_payload_key_inferred"] = leftover[0]
    return result


def parse_dex_strings(dex: bytes) -> list[str]:
    if dex[:4] != b"dex\n" or len(dex) < 0x70:
        raise ValueError("not a DEX file")
    count, table = struct.unpack_from("<II", dex, 56)
    strings = []
    for i in range(count):
        try:
            p = struct.unpack_from("<I", dex, table + i * 4)[0]
            while dex[p] & 0x80:  # ULEB128 utf16 length
                p += 1
            p += 1
            end = dex.index(b"\x00", p)
        except (struct.error, IndexError, ValueError):
            break
        strings.append(dex[p:end].decode("utf-8", errors="replace"))
    return strings


def decode_stringfog_arrays(dex: bytes) -> list[str]:
    arrays = []
    pos = 0
    while True:
        idx = dex.find(b"\x00\x03\x01\x00", pos)
        if idx == -1:
            break
        pos = idx + 2
        if idx % 2 or idx + 8 > len(dex):
            continue
        size = struct.unpack_from("<I", dex, idx + 4)[0]
        if 1 <= size <= 8192 and idx + 8 + size <= len(dex):
            arrays.append((idx, dex[idx + 8 : idx + 8 + size]))
    out = []
    i = 0
    while i + 1 < len(arrays):
        (o1, ct), (o2, key) = arrays[i], arrays[i + 1]
        if len(key) == 8 and 0 <= o2 - (o1 + 8 + len(ct)) <= 3:
            try:
                s = xor_repeat(ct, key).decode("utf-8")
            except UnicodeDecodeError:
                i += 1
                continue
            if all(c.isprintable() or c in "\r\n\t" for c in s):
                out.append(s)
                i += 2
                continue
        i += 1
    return out


def decode_b64_xor_domains(candidates: list[str], key: str) -> dict[str, str]:
    out = {}
    kb = key.encode("utf-8")
    if not kb:
        return out
    for s in candidates:
        try:
            dec = xor_repeat(base64.b64decode(s, validate=True), kb).decode("ascii")
        except (ValueError, UnicodeDecodeError):
            continue
        if DOMAIN_RE.fullmatch(dec):
            out[s] = dec
    return out


def b64_candidates_from(strings: list[str]) -> list[str]:
    return sorted({s for s in strings if len(s) >= 12 and len(s) % 4 == 0 and B64_RE.fullmatch(s)})


def extract_stage3_dex_config(dex: bytes, domain_key: str | None) -> dict:
    plain = parse_dex_strings(dex)
    fogged = decode_stringfog_arrays(dex)
    everything = list(dict.fromkeys(plain + fogged))
    cfg: dict = {"stringfog_strings_recovered": len(fogged)}

    cfg["c2_domains_b64_map"] = decode_b64_xor_domains(b64_candidates_from(everything), domain_key or "")
    cfg["doh_resolvers"] = sorted(s for s in everything if re.fullmatch(r"https://[\d.]+/(resolve|dns-query)", s))

    fcm: dict = {}
    app_id = next((s for s in fogged if re.fullmatch(r"1:\d{10,14}:android:[0-9a-f]{16,32}", s)), None)
    fcm["app_id"] = app_id
    fcm["gcm_sender_id"] = app_id.split(":")[1] if app_id else None
    fcm["api_key"] = next((s for s in fogged if re.fullmatch(r"AIzaSy[A-Za-z0-9_-]{33}", s)), None)
    project = None
    for s in fogged:
        m = re.search(r"PROJECT_ID=([a-z][a-z0-9-]{4,28}[a-z0-9])", s)
        if m and m.group(1) in fogged:
            project = m.group(1)
            break
    if project is None and app_id:
        i = fogged.index(app_id)
        near = [s for s in fogged[max(0, i - 3) : i + 4]
                if re.fullmatch(r"[a-z][a-z0-9-]{4,28}[a-z0-9]", s) and "-" in s]
        project = near[0] if len(near) == 1 else None
    fcm["project_id"] = project
    cfg["fcm"] = fcm

    reality: dict = {"default_sni": None, "default_short_id": None}
    pairs = {(a, b) for a, b in zip(fogged, fogged[1:])
             if HOSTNAME_RE.fullmatch(a) and re.fullmatch(r"(?:[0-9a-f]{2}){2,8}", b)}
    if len(pairs) == 1:
        reality["default_sni"], reality["default_short_id"] = next(iter(pairs))
    elif pairs:
        reality["default_sni_candidates"] = sorted(f"{a} / {b}" for a, b in pairs)
    anchors = set(cfg["c2_domains_b64_map"]) | set(cfg["doh_resolvers"])
    uuids = set()
    for i, s in enumerate(fogged):
        if UUID_RE.fullmatch(s) and anchors & set(fogged[max(0, i - 2) : i + 3]):
            uuids.add(s)
    reality["vless_uuid_inferred"] = sorted(uuids)
    cfg["reality"] = reality

    cfg["c2_alt_ports"] = sorted({
        int(s[1:]) for s in everything
        if re.fullmatch(r":\d{2,5}", s) and 1 <= int(s[1:]) <= 65535
    })
    cfg["c2_ws_strings"] = sorted({s for s in everything
                                   if re.fullmatch(r"/ws[\w/?=&-]*", s) or "uuid=" in s and len(s) < 64})

    ip_urls = set()
    for s in b64_candidates_from(everything):
        try:
            d = base64.b64decode(s, validate=True).decode("ascii")
        except (ValueError, UnicodeDecodeError):
            continue
        if d.startswith(("http://", "https://")):
            ip_urls.add(d)
    cfg["ip_geo_urls"] = sorted(ip_urls)
    return cfg


def redact_token(token: str) -> str:
    bot_id = token.split(":", 1)[0]
    return f"{bot_id}:<redacted; sha256={hashlib.sha256(token.encode()).hexdigest()}>"


def extract_all(apk_path: Path, raw_iocs: bool, show_secrets: bool, user_key32: bytes | None) -> dict:
    errors: list[str] = []
    report: dict = {"tool_version": TOOL_VERSION, "errors": errors}

    def dfg(v):
        return v if raw_iocs or v is None else defang(v)

    def stage(name, fn):
        try:
            return fn()
        except Exception as exc:
            errors.append(f"{name}: {type(exc).__name__}: {exc}")
            return None

    s1 = apk_path.read_bytes()
    s1_info: dict = {"file": str(apk_path), "hashes": hashes_of(s1)}
    report["stage1_dropper"] = s1_info
    s1_info["certificates"] = stage("stage1 certificates", lambda: extract_apk_sig_block_certs(s1)) or []
    entries = stage("stage1 zip", lambda: read_zip_entries_raw(s1))
    if entries is None:
        return report
    s1_info["zip_anomalies"] = zip_anomalies(entries)

    encrypted = [e for e in entries if e["content"] and e["content"].startswith(STAGE1_ASSET_MAGIC)]
    payload = max(encrypted, key=lambda e: len(e["content"]), default=None)
    if payload is None or len(payload["content"]) < 100_000:
        errors.append("stage1: no encrypted payload asset with magic c93b7a4f found")
        return report
    s1_info["encrypted_payload_asset"] = payload["name"]

    other = []
    for e in encrypted:
        if e is payload:
            continue
        k4, dec = decrypt_stage1_asset(e["content"], None)
        other.append({"asset": e["name"], "key4_hex": k4.hex(), "decrypted_size": len(dec),
                      "decrypted_sha256": hashlib.sha256(dec).hexdigest(),
                      "looks_like_html": b"<html" in dec[:2048].lower() or b"<!doctype" in dec[:2048].lower()})
    s1_info["other_encrypted_assets"] = other

    key32, key_source = None, None
    for e in entries:
        if re.fullmatch(r"classes\d*\.dex", e["name"]) and e["content"]:
            key32 = find_stage1_key32_in_dex(e["content"], payload["content"])
            if key32:
                key_source = f"recovered from {e['name']} (fill-array-data, validated by inflating to a ZIP)"
                break
    if key32 is None and user_key32 is not None:
        key32, key_source = user_key32, "supplied with --key32 (NOT recovered from the sample)"
    if key32 is None:
        errors.append("stage1: 32-byte XOR key not found in classes.dex; pass --key32 HEX to continue")
        return report
    s1_info["payload_key32_hex"] = key32.hex()
    s1_info["payload_key32_source"] = key_source

    def unwrap_stage2():
        k4, body = decrypt_stage1_asset(payload["content"], key32)
        s1_info["payload_key4_hex"] = k4.hex()
        return inflate_limited(body, 15, MAX_STAGE_SIZE)

    s2 = stage("stage1 payload decrypt", unwrap_stage2)
    if s2 is None:
        return report

    s2_info: dict = {"hashes": hashes_of(s2)}
    report["stage2_template_apk"] = s2_info
    s2_info["note"] = ("Template as embedded in Stage 1. The dropper renames the package and signs it again "
                       "on the device, so this hash, certificate, and package name are not expected on victims.")
    s2_info["certificates"] = stage("stage2 certificates", lambda: extract_apk_sig_block_certs(s2)) or []
    s2_entries_list = stage("stage2 zip", lambda: read_zip_entries_raw(s2))
    if s2_entries_list is None:
        return report
    s2_files = {}
    for e in s2_entries_list:
        if e["content"] is not None:
            if e["name"] not in s2_files or len(e["content"]) > 0:
                s2_files[e["name"]] = e["content"]
    s2_info["zip_anomalies"] = zip_anomalies(s2_entries_list)
    s2_info["native_abis"] = sorted({n.split("/")[1] for n in s2_files if n.startswith("lib/") and n.count("/") == 2})
    arm64 = {n: b for n, b in s2_files.items() if n.startswith("lib/arm64-v8a/") and n.endswith(".so")}
    if not arm64:
        errors.append("stage2: no lib/arm64-v8a libraries; native parsing supports AArch64 only")
    stub_dexes = [b for n, b in s2_files.items() if re.fullmatch(r"classes\d*\.dex", n)]

    s3 = None
    asset_names = {n for n in s2_files if n.startswith("assets/")}
    for name, blob in sorted(arm64.items(), key=lambda kv: len(kv[1])):
        if b"AAssetManager_open" not in blob or b"inflateInit2_" not in blob:
            continue
        try:
            shards, s2_key = extract_stage2_loader_params(blob, asset_names, s2_files)
            joined = b"".join(s2_files[f"assets/{p}"] for p in shards)
            s3 = inflate_limited(xor_repeat(joined, s2_key), 47, MAX_STAGE_SIZE)
        except Exception as exc:
            errors.append(f"stage2 loader {name}: {type(exc).__name__}: {exc}")
            continue
        s2_info.update({"native_dex_loader": name, "dex_shard_order": [f"assets/{p}" for p in shards],
                        "dex_xor_key32_hex": s2_key.hex()})
        break
    if s3 is None and not any(e.startswith("stage2 loader") for e in errors):
        errors.append("stage2: native DEX loader (AAssetManager_open + inflateInit2_) not found")

    s3_strings: list[str] = []
    if s3 is not None:
        report["stage3_payload_dex"] = {
            "hashes": hashes_of(s3),
            "dex_magic": s3[:8].decode("ascii", errors="replace").strip("\x00\n"),
        }
        s3_strings = stage("stage3 strings", lambda: parse_dex_strings(s3) + decode_stringfog_arrays(s3)) or []
    dex_blobs = stub_dexes + ([s3] if s3 is not None else [])

    native_cfg: dict = {}
    best_len = 0
    for name, blob in arm64.items():
        try:
            decoded = decode_caesar_callsites(blob)
        except Exception:
            continue
        if len(decoded["strings"]) > best_len and len(decoded["strings"]) >= 3:
            best_len = len(decoded["strings"])
            native_cfg = stage(
                "native config", lambda: interpret_native_config(decoded, blob, dex_blobs, b64_candidates_from(s3_strings))
            ) or {}
            native_cfg["library"] = name
    if not native_cfg:
        errors.append("stage2: no library with a recognizable Caesar string decoder")
    s2_info["native_config_lib"] = native_cfg.get("library")
    s2_info["native_reality_lib"] = next(
        (n for n, b in arm64.items() if b"RealityTransport_nativeConnect" in b), None)

    orphans = []
    for name, blob in arm64.items():
        for e in jni_exports(blob):
            present = any((b"L" + e["class"].encode() + b";") in d for d in dex_blobs)
            if not present and "RealityTransport" not in e["class"] and not e["class"].startswith("androidx/"):
                orphans.append({"library": name, "symbol": e["symbol"]})
    s2_info["jni_exports_without_java_class"] = orphans

    s3_cfg = stage("stage3 config", lambda: extract_stage3_dex_config(s3, native_cfg.get("domain_b64_xor_key"))) \
        if s3 is not None else None
    s3_cfg = s3_cfg or {}

    telegram = dict(native_cfg.get("telegram", {}))
    if telegram:
        if "bot_token" in telegram:
            telegram["bot_id"] = telegram["bot_token"].split(":", 1)[0]
            if not show_secrets:
                telegram["bot_token"] = redact_token(telegram["bot_token"])
        telegram["gate_url"] = dfg(telegram.get("gate_url"))
        telegram["status"] = (
            "referenced by Java code in this build" if telegram.get("getter_class_present_in_dex")
            else "dormant: returned only by exported JNI getters whose Java class is absent from every DEX in this build"
        )

    reality = s3_cfg.get("reality", {})
    report["extracted_config"] = {
        "bot_id_format_inferred": "<bot_id_prefix>-<uuid>-<bot_id_suffix>",
        "bot_id_prefix": native_cfg.get("bot_id_prefix"),
        "bot_id_suffix": native_cfg.get("bot_id_suffix"),
        "jni_config_class": native_cfg.get("jni_config_class"),
        "domain_b64_xor_key": native_cfg.get("domain_b64_xor_key"),
        "c2_payload_key_inferred": native_cfg.get("c2_payload_key_inferred"),
        "c2_payload_transform": ("device->server frames are {\"p\": base64(pt[i] ^ (i & 0xff) ^ key[i % len(key)])}"
                                 " (native mdnaboec); server->device commands are plain JSON. See fh_c2crypto.py"),
        "c2_domains_b64_map": {k: dfg(v) for k, v in s3_cfg.get("c2_domains_b64_map", {}).items()},
        "c2_hostname_roles_this_build": {
            "all1.<newglnbsj host> (prefix added in code)": "DoH TXT name -> list of WebSocket backend domains",
            "all1.<realdd host>": "DoH TXT name -> REALITY server records host:port:pubkey[:sni:shortId]",
            "<dakjdnwgnn host>": "hardcoded fallback backend host",
        },
        "c2_alt_ports": s3_cfg.get("c2_alt_ports", []),
        "c2_ws_strings": s3_cfg.get("c2_ws_strings", []),
        "reality": {
            "vless_uuid_inferred": reality.get("vless_uuid_inferred", []),
            "default_sni": dfg(reality.get("default_sni")),
            "default_short_id": reality.get("default_short_id"),
            **({"default_sni_candidates": [dfg(c) for c in reality["default_sni_candidates"]]}
               if "default_sni_candidates" in reality else {}),
        },
        "doh_resolvers_public_do_not_block": [dfg(u) for u in s3_cfg.get("doh_resolvers", [])],
        "fcm": s3_cfg.get("fcm", {}),
        "ip_geo_urls_public_do_not_block": [dfg(u) for u in s3_cfg.get("ip_geo_urls", [])],
        "telegram": telegram or None,
        "native_caesar": {
            "decoder_va": native_cfg.get("decoder_va"),
            "shifts_seen": native_cfg.get("shifts_seen", []),
            "strings_decoded": len(native_cfg.get("decoded_strings", [])),
            "unresolved_callsites": native_cfg.get("unresolved_callsites"),
        },
        "stringfog_strings_recovered": s3_cfg.get("stringfog_strings_recovered"),
    }
    return report


def main() -> int:
    ap = argparse.ArgumentParser(description="Offline static config extractor for До_Вылета.apk")
    ap.add_argument("apk", type=Path, help="path to the Stage 1 APK")
    ap.add_argument("--raw", action="store_true", help="do not defang URLs/domains")
    ap.add_argument("--show-secrets", action="store_true", help="print the Telegram bot token in full")
    ap.add_argument("--key32", metavar="HEX", help="Stage 1 32-byte XOR key fallback if DEX scan fails")
    args = ap.parse_args()

    user_key = None
    if args.key32:
        try:
            user_key = bytes.fromhex(args.key32)
        except ValueError:
            ap.error("--key32 must be hexadecimal")
        if len(user_key) != 32:
            ap.error("--key32 must be exactly 32 bytes (64 hex characters)")

    try:
        report = extract_all(args.apk, args.raw, args.show_secrets, user_key)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, ensure_ascii=False))
    if report["errors"]:
        print(f"completed with {len(report['errors'])} error(s); see \"errors\"", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
