#!/usr/bin/env python3
"""Structured seed generator for fuzz_tls13_server.

Emits TLS 1.3 client-flight seeds: well-formed ClientHello records with
supported_versions / key_share / signature_algorithms / PSK extensions, an
HRR-retry double flight, and PSK-binder variants. The external-PSK binders
are *valid*: the generator replicates the TLS 1.3 binder key schedule
(HKDF-Expand-Label over the "ext binder" derivative of the external PSK) for
the harness's static PSK (16 bytes 0x00..0x0f, identity "Client_identity",
SHA-256 ciphersuites), so the server-side binder comparison succeeds and the
handshake proceeds past ClientHello verification — a mutation-resistant gate
(record framing + extension structure + a truncated-transcript HMAC binder
cannot be produced by blind mutation).

The last byte of every seed is the harness options byte (see the harness
header); it is appended from the seed spec below.
"""
import argparse
import hmac
import hashlib
import os

PSK = bytes(range(16))
IDENTITY = b"Client_identity"
SHA256_LEN = 32


def u8(n):
    return bytes([n])


def u16(n):
    return n.to_bytes(2, "big")


def u24(n):
    return n.to_bytes(3, "big")


def ext(t, body):
    return u16(t) + u16(len(body)) + body


def hkdf_extract(salt, ikm):
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk, info, length):
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


def expand_label(secret, label, context, length):
    full = b"tls13 " + label
    info = u16(length) + u8(len(full)) + full + u8(len(context)) + context
    return hkdf_expand(secret, info, length)


def derive_secret(secret, label, msgs_hash):
    return expand_label(secret, label, msgs_hash, SHA256_LEN)


def compute_binder(ch_truncated):
    """TLS 1.3 external-PSK binder for SHA-256 ciphersuites."""
    empty_hash = hashlib.sha256(b"").digest()
    early_secret = hkdf_extract(b"\x00" * SHA256_LEN, PSK)
    binder_key = derive_secret(early_secret, b"ext binder", empty_hash)
    transcript = hashlib.sha256(ch_truncated).digest()
    finished_key = expand_label(binder_key, b"finished", b"", SHA256_LEN)
    return hmac.new(finished_key, transcript, hashlib.sha256).digest()


def client_hello(random32, sid32, suites, exts,
                 psk_identities=None):
    """ClientHello handshake message; zero-filled binder if psk given.

    Returns (msg, binders_pos) where binders_pos is the offset of the
    binders list (its 2-byte length) inside msg, or None. msg[:binders_pos]
    is the RFC 8446 section 4.2.11.2 truncated transcript.
    """
    body = (b"\x03\x03" + random32 + u8(len(sid32)) + sid32 +
            u16(len(suites)) + suites + b"\x01\x00")
    ext_blob = b""
    for t, b in exts:
        ext_blob += ext(t, b)
    binders_pos = None
    if psk_identities is not None:
        binders = u16(1 + SHA256_LEN) + u8(SHA256_LEN) + b"\x00" * SHA256_LEN
        ext_blob += ext(41, u16(len(psk_identities)) + psk_identities +
                        binders)
        binders_pos = 4 + len(body) + 2 + len(ext_blob) - len(binders)
    body += u16(len(ext_blob)) + ext_blob
    msg = u8(1) + u24(len(body)) + body
    return msg, binders_pos


def splice_binder(msg, binders_pos, binder):
    assert len(binder) == SHA256_LEN
    start = binders_pos + 3
    return msg[:start] + binder + msg[start + SHA256_LEN:]


TLS13_SUITES = bytes.fromhex("130113021303")
TLS13_PLUS_12_SUITES = bytes.fromhex("130113021303c02bc030")
P256_GX = bytes.fromhex("6b17d1f2e12c4247f8bce6e563a440f2"
                        "77037d812deb33a0f4a13945d898c296")
P256_GY = bytes.fromhex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e1"
                        "62bce33576b315ececbb6406837bf51f5")

SID = bytes(range(32))
RND = bytes([(i * 11 + 1) & 0xFF for i in range(32)])


def key_share_ext(groups):
    shares = b""
    if 0x001d in groups:
        shares += u16(0x001d) + u16(32) + bytes(range(32))
    if 0x0017 in groups:
        shares += u16(0x0017) + u16(65) + b"\x04" + P256_GX + P256_GY
    if shares:
        return [(51, u16(len(shares)) + shares)]  # 51 = 0x0033 key_share
    return []


def base_exts(groups, sigalgs=True):
    exts = []
    if sigalgs:
        algs = bytes.fromhex("040305030804080504010501")
        exts.append((13, u16(len(algs)) + algs))
    exts.append((10, u16(2 * len(groups)) +
                 b"".join(u16(g) for g in groups)))
    exts += key_share_ext(groups)
    # supported_versions (43): 1-byte list length 2 + TLS 1.3 (0x0304)
    exts.append((43, u8(2) + b"\x03\x04"))
    return exts


def psk_seed(name, groups, dhe, good, opts):
    exts = base_exts(groups)
    exts.append((45, u8(1) + u8(1 if dhe else 0)))
    ident = u16(len(IDENTITY)) + IDENTITY + (0).to_bytes(4, "big")
    if good:
        msg, bpos = client_hello(RND, SID, TLS13_SUITES, exts,
                                 psk_identities=ident)
        msg = splice_binder(msg, bpos, compute_binder(msg[:bpos]))
    else:
        bad = bytes([(i * 17 + 5) & 0xFF for i in range(32)])
        msg, bpos = client_hello(RND, SID, TLS13_SUITES, exts,
                                 psk_identities=ident)
        msg = splice_binder(msg, bpos, bad)
    return {name: record(msg) + u8(opts)}


def record(handshake):
    return bytes([22]) + b"\x03\x03" + u16(len(handshake)) + handshake


def build_seeds():
    seeds = {}

    # 1/2. plain ephemeral ClientHello (x25519, P-256 with valid curve point)
    msg, _ = client_hello(RND, SID, TLS13_SUITES, base_exts([0x001d, 0x0017]))
    seeds["ch_x25519"] = record(msg) + b"\x00"
    msg, _ = client_hello(RND, SID, TLS13_SUITES, base_exts([0x0017]))
    seeds["ch_p256"] = record(msg) + b"\x00"

    # 3. HRR flow: x25519-only CH then a P-256 retry CH (options 0x08)
    exts1 = [e for e in base_exts([0x001d, 0x0017]) if e[0] != 51]
    exts1 += key_share_ext([0x001d])  # offer P-256, share x25519 only
    msg1, _ = client_hello(RND, SID, TLS13_SUITES, exts1)
    msg2, _ = client_hello(bytes([(i * 3 + 7) & 0xFF for i in range(32)]),
                           SID, TLS13_SUITES, base_exts([0x0017]))
    seeds["ch_hrr_retry"] = record(msg1) + record(msg2) + b"\x08"

    # 4/5/6. external-PSK flights (valid psk_ke / psk_dhe_ke binders + corrupt)
    seeds.update(psk_seed("ch_psk_ke", [], False, True, 0x01))
    seeds.update(psk_seed("ch_psk_dhe", [0x001d, 0x0017], True, True, 0x01))
    seeds.update(psk_seed("ch_psk_bad_binder", [], False, False, 0x01))

    # 7. TLS 1.2 fallback (no supported_versions, 1.2 suites, options 0x20)
    msg, _ = client_hello(RND, SID, bytes.fromhex("c02bc030002f0035"),
                          base_exts([0x001d, 0x0017]))
    seeds["ch_tls12_fallback"] = record(msg) + b"\x20"

    # 8. malformed extension zoo
    exts = base_exts([0x001d])
    exts.append((0x0aff, b"\x00\x01\x02"))
    exts.append((33, u16(2) + u16(0x001d)))           # share without key bytes
    exts.append((10, u16(4) + u16(0x001d) + u16(0x001d)))
    msg, _ = client_hello(RND, SID, TLS13_SUITES, exts)
    seeds["ch_malformed_exts"] = record(msg) + b"\x00"

    # 9. ALPN + tickets options
    exts = base_exts([0x001d, 0x0017])
    exts.append((16, u16(11) + u8(10) + b"fuzzalpn13"))
    msg, _ = client_hello(RND, SID, TLS13_SUITES, exts)
    seeds["ch_alpn_tickets"] = record(msg) + b"\x06"

    # 10. junk application-data record after the ClientHello
    msg, _ = client_hello(RND, SID, TLS13_SUITES, base_exts([0x001d, 0x0017]))
    junk = bytes([23]) + b"\x03\x03" + u16(24) + bytes(range(24))
    seeds["ch_then_appdata_junk"] = record(msg) + junk + b"\x00"

    # 11. GREASE suite/group/extension values
    exts = [(0x0a0a, b"\x00\x00")] + base_exts([0x001d, 0x0017])
    msg, _ = client_hello(RND, SID, bytes.fromhex("0a0a1301c02bc030"), exts)
    seeds["ch_grease"] = record(msg) + b"\x00"

    # 12. empty key_share extension (HRR decision logic)
    exts = base_exts([0x001d, 0x0017])
    exts.append((33, u16(0)))
    msg, _ = client_hello(RND, SID, TLS13_SUITES, exts)
    seeds["ch_empty_keyshare"] = record(msg) + b"\x00"

    # 13. post-handshake messages and a second connection attempt in one input
    msg, _ = client_hello(RND, SID, TLS13_SUITES, base_exts([0x001d, 0x0017]))
    msg2, _ = client_hello(bytes([(i * 5 + 2) & 0xFF for i in range(32)]),
                           SID, TLS13_SUITES, base_exts([0x001d, 0x0017]))
    keyupdate = bytes([24]) + b"\x03\x03" + u16(4) + bytes([8, 0, 0, 0])
    seeds["ch_two_flights"] = (record(msg) + keyupdate + record(msg2) +
                               b"\x00")

    return seeds


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    all_seeds = build_seeds()
    for name, blob in all_seeds.items():
        with open(os.path.join(args.out, name), "wb") as fh:
            fh.write(blob)
    print("wrote %d seeds to %s" % (len(all_seeds), args.out))


if __name__ == "__main__":
    main()
