#!/usr/bin/env python3
"""Structured seed generator for fuzz_psa_crypto (OSS-Fuzz coverage pipeline
pair 1, mbedtls-psa-crypto).

Emits op-script seeds for the stateful PSA API harness, one seed per
algorithm family, so the mutator starts inside the family instead of having
to discover valid PSA attribute combinations through the single-byte
selector encoding (a mutation-resistant gate: attribute selectors and
key-material formats such as DER RSAPrivateKey / raw ECC scalars).

RSA private-key material is taken from an existing framework PEM file
(BEGIN RSA PRIVATE KEY = PKCS#1 DER, exactly the PSA import format), so no
key generation is needed here and the bytes are deterministic.

Usage:
    python3 generate_psa_crypto_seeds.py --out DIR [--rsa-pem FILE]

Byte layout mirrors fuzz_psa_crypto.c exactly (see the harness header).
"""
import argparse
import base64
import os
import re
import sys

K32 = bytes((i * 7 + 11) & 0xFF for i in range(32))
K16 = bytes((i * 13 + 5) & 0xFF for i in range(16))
K8 = bytes((i * 29 + 3) & 0xFF for i in range(8))
PT = bytes((i * 31 + 7) & 0xFF for i in range(64))

# key type selectors (key_type_from_sel)
T_RAW, T_HMAC, T_AES, T_ARIA, T_CAM, T_CHACHA, T_DES = 0, 1, 2, 3, 4, 5, 6
T_RSA_PUB, T_RSA_PRIV, T_EC_R1, T_EC_K1, T_EC_MONT, T_DH, T_PASSWD = \
    7, 8, 9, 10, 11, 12, 13
T_DERIVE = 14

# op codes (LLVMFuzzerTestOneInput switch)
O_IMP, O_GEN, O_HASH, O_MAC, O_CIPH, O_AEAD = 0, 1, 2, 3, 4, 5
O_SIGN_H, O_VER_H, O_SIGN_M, O_VER_M, O_AENC, O_ADEC = 6, 7, 8, 9, 10, 11
O_AGR, O_KDF, O_EXP, O_EXPP, O_COPY, O_PURGE = 12, 13, 14, 15, 16, 17
O_IMPP, O_GENP, O_RAND, O_OPEN = 18, 19, 20, 21

# hash selectors (hash_from_sel)
H_MD5, H_SHA1, H_SHA224, H_SHA256, H_SHA384, H_SHA512, H_RIPEMD160 = \
    0, 1, 2, 3, 4, 5, 6
H_SHA3_224, H_SHA3_256, H_SHA3_512 = 7, 8, 9
HASH_LEN = {H_SHA256: 32, H_SHA384: 48, H_SHA512: 64, H_SHA3_512: 64}

# cipher selectors (cipher_from_sel)
C_STREAM, C_CTR, C_CFB, C_ECB, C_CBC_NOPAD, C_CBC_PKCS7 = 0, 1, 2, 3, 4, 5


# Algorithm byte pairs, in the order the harness reads them: [s, hsel] or
# [s, tag_sel] (see the *_from_sel functions).
def mac_hmac(h):
    return [1, h]


MAC_CMAC = [0, 0]


def sig(kind, h):
    """kind: 0 PKCS1V15, 1 PKCS1V15 raw, 2 PSS, 3 PSS any salt, 4 ECDSA,
    5 deterministic ECDSA"""
    return [kind, h]


def kdf(kind, h):
    """kind: 0 HKDF, 1 HKDF-Extract, 2 HKDF-Expand, 3 TLS12-PRF,
    4 TLS12-PSK-to-MS, 5 PBKDF2-HMAC"""
    return [kind, h]


A_GCM, A_CCM, A_CHACHAPOLY = 0, 1, 2


def aead(kind, tag_len=None):
    """Default tag, or a shortened tag of 4..19 bytes."""
    if tag_len is None:
        return [kind, 0]
    return [kind, 1 | ((tag_len - 4) << 2)]


def oaep(h):
    return [1, h]


# algsel for import: odd = cipher, even = family index * 2
I_CIPHER = 1
I_HASH, I_MAC, I_SIG, I_KDF, I_AEAD, I_ASYM = 0, 2, 4, 6, 8, 10
# algsel for generate: odd = cipher, even = family index * 2
G_CIPHER = 1
G_MAC, G_SIG, G_AEAD, G_ASYM, G_AGREE = 0, 2, 4, 6, 8
AGREE_ECDH, AGREE_FFDH = [0], [1]

# key size selectors (key_bits_from_sel)
B_AES128, B_AES192, B_AES256 = 0, 1, 3
B_P224, B_P256, B_P384, B_P521 = 0, 2, 1, 3
B_X25519, B_X448 = 0, 1
B_FFDH2048, B_FFDH3072 = 0, 1
B_DES3 = 2                                           # 192-bit (3-key) DES


# KDF step selectors (op_kdf: sel % 7)
S_SECRET, S_PASSWORD, S_SALT, S_LABEL, S_INFO, S_SEED, S_OTHER_SECRET = \
    0, 1, 2, 3, 4, 5, 6
S_COST = 0x80                       # integer input, then count - 1


def key_step(step):
    """Selector for a key input: bit 6 set, and still step modulo 7."""
    sel = 0x40
    while sel % 7 != step:
        sel += 1
    return sel


def u16(n):
    return [n & 0xFF, (n >> 8) & 0xFF]


def blob8(data):
    """1-byte length + bytes"""
    return [len(data)] + list(data)


def blob16(data):
    """2-byte LE length + bytes"""
    return u16(len(data)) + list(data)


def imp(typesel, keybytes, algsel, algbytes, persistent=None):
    """import: type, len(2 LE), bytes, algsel, alg bytes [, id]"""
    out = [O_IMPP if persistent is not None else O_IMP, typesel] + \
        blob16(keybytes) + [algsel] + list(algbytes)
    if persistent is not None:
        out.append(persistent)
    return out


def gen(typesel, bitsel, algsel, algbytes, persistent=None):
    """generate: type, bits, algsel, alg bytes [, id]"""
    out = [O_GENP if persistent is not None else O_GEN, typesel, bitsel,
           algsel] + list(algbytes)
    if persistent is not None:
        out.append(persistent)
    return out


def script(*ops):
    return bytes([len(ops)] + sum(([int(b) for b in op] for op in ops), []))


def cap(bits):
    """KDF capacity as 2-byte LE (harness: (get16 & 0xFFF) * 8 + 1)."""
    return u16(max(0, (bits - 1) // 8))


def seeds(rsa_der):
    out = {}
    # key slot 0 is the first key created in the script
    K = 0

    # op_hash: hsel, sub, len8, data [, digest when sub & 2]
    out["hash_sha256_clone"] = script(
        [O_HASH, H_SHA256, 1] + blob8(K32))
    out["hash_sha3_512_verify"] = script(
        [O_HASH, H_SHA3_512, 2] + blob8(K32) +
        list(PT[:HASH_LEN[H_SHA3_512]]))             # mismatching digest
    out["hash_ripemd160"] = script(
        [O_HASH, H_RIPEMD160, 0] + blob8(K16))

    # op_mac: key, hsel, msel, len8, data, vlen8, v
    #   msel: bit 0 HMAC (else CMAC), bit 1 multipart, bit 2 multipart verify
    out["hmac_sha256"] = script(
        imp(T_HMAC, K32, I_MAC, mac_hmac(H_SHA256)),
        [O_MAC, K, H_SHA256, 1] + blob8(K32) + blob8(b""),
        [O_MAC, K, H_SHA256, 3] + blob8(K16) + blob8(b""))
    out["cmac_aes"] = script(
        imp(T_AES, K16, I_MAC, MAC_CMAC),
        [O_MAC, K, 0, 2] + blob8(K16) + blob8(b""),
        [O_MAC, K, 0, 6] + blob8(K16) + blob8(K16))  # wrong tag

    # op_cipher: key, cipher, mode, len8, data, ivlen8, iv
    #   mode: bit 0 one-shot round trip (else decrypt the data as IV||ct),
    #   bit 1 multipart, bit 2 multipart decrypt with set_iv
    out["aes_cbc_pkcs7"] = script(
        imp(T_AES, K16, I_CIPHER, [C_CBC_PKCS7]),
        [O_CIPH, K, C_CBC_PKCS7, 1] + blob8(PT[:32]) + blob8(K16))
    out["aes_ctr_multipart"] = script(
        imp(T_AES, K16, I_CIPHER, [C_CTR]),
        [O_CIPH, K, C_CTR, 2] + blob8(PT) + blob8(b""))
    out["aes_cfb_decrypt_mp"] = script(
        imp(T_AES, K16, I_CIPHER, [C_CFB]),
        [O_CIPH, K, C_CFB, 6] + blob8(K16) + blob8(K16))
    out["des_cbc"] = script(
        gen(T_DES, B_DES3, G_CIPHER, [C_CBC_PKCS7]),
        [O_CIPH, K, C_CBC_PKCS7, 1] + blob8(K8) + blob8(K8))

    # op_aead: key, tsel, nsel, nonce8, ad8, data8
    #   nsel: bit 0 one-shot round trip (else decrypt the data),
    #   bit 1 multipart set_nonce (else generate_nonce), bits 2+ tag selector
    out["aes_gcm"] = script(
        imp(T_AES, K16, I_AEAD, aead(A_GCM)),
        [O_AEAD, K, A_GCM, 3] + blob8(K16[:12]) + blob8(K8) + blob8(PT[:32]))
    out["aes_ccm_shorttag"] = script(
        imp(T_AES, K16, I_AEAD, aead(A_CCM, 6)),
        [O_AEAD, K, A_CCM, 1 | (aead(A_CCM, 6)[1] << 2)] +
        blob8(K16[:12]) + blob8(K8[:4]) + blob8(K16))
    out["chachapoly"] = script(
        imp(T_CHACHA, K32, I_AEAD, aead(A_CHACHAPOLY)),
        [O_AEAD, K, A_CHACHAPOLY, 3] + blob8(K16[:12]) + blob8(K8[:4]) +
        blob8(PT[:24]))
    out["aria_gcm"] = script(
        gen(T_ARIA, B_AES128, G_AEAD, aead(A_GCM)),
        [O_AEAD, K, A_GCM, 3] + blob8(K16[:12]) + blob8(K8[:4]) + blob8(K16))
    out["camellia_ccm"] = script(
        gen(T_CAM, B_AES128, G_AEAD, aead(A_CCM)),
        [O_AEAD, K, A_CCM, 3] + blob8(K16[:12]) + blob8(K8[:4]) + blob8(K16))

    # op_sign_verify_*: key, s, hsel, len8, hash/msg, vlen16, sig
    if rsa_der is not None:
        out["rsa_pkcs1v15_sign"] = script(
            imp(T_RSA_PRIV, rsa_der, I_SIG, sig(0, H_SHA256)),
            [O_SIGN_H, K] + sig(0, H_SHA256) + blob8(K32) + blob16(b""),
            [O_VER_H, K] + sig(0, H_SHA256) + blob8(K32) +
            blob16(PT * 4))                          # 256-byte wrong sig
        out["rsa_pss_message"] = script(
            imp(T_RSA_PRIV, rsa_der, I_SIG, sig(2, H_SHA256)),
            [O_SIGN_M, K] + sig(2, H_SHA256) + blob8(PT[:48]) + blob16(b""))
        # op_asymmetric: key, s, hsel, len16, input, saltlen8, salt
        out["rsa_oaep"] = script(
            imp(T_RSA_PRIV, rsa_der, I_ASYM, oaep(H_SHA256)),
            [O_AENC, K] + oaep(H_SHA256) + blob16(K32) + blob8(b""),
            [O_ADEC, K] + oaep(H_SHA256) + blob16(PT * 4) +  # bad padding
            blob8(b""))

    out["ecdsa_p256"] = script(
        imp(T_EC_R1, K32, I_SIG, sig(4, H_SHA256)),
        [O_SIGN_H, K] + sig(4, H_SHA256) + blob8(K32) + blob16(b""),
        [O_VER_H, K] + sig(4, H_SHA256) + blob8(K32) + blob16(PT[:64]))
    out["ecdsa_det_p384"] = script(
        gen(T_EC_R1, B_P384, G_SIG, sig(5, H_SHA384)),
        [O_SIGN_H, K] + sig(5, H_SHA384) + blob8(PT[:48]) + blob16(b""))

    # op_key_agreement: key, asel (bit 0 FFDH, else ECDH), peer16
    out["x25519_agreement"] = script(
        gen(T_EC_MONT, B_X25519, G_AGREE, AGREE_ECDH),
        [O_AGR, K, 0] + blob16(K32))
    out["p256_agreement"] = script(
        gen(T_EC_R1, B_P256, G_AGREE, AGREE_ECDH),
        [O_AGR, K, 0] + blob16(bytes([0x04]) + K32 + K32))  # not on curve
    out["ffdh_2048"] = script(
        gen(T_DH, B_FFDH2048, G_AGREE, AGREE_FFDH),
        [O_AGR, K, 1] + blob16(PT * 4))

    # op_kdf: s, hsel, steps, cap16, steps..., outs, outputs...
    #   step: sel (bit 7 = COST, then count - 1; bit 6 = key input, then key;
    #   else len8 + bytes)
    #   output j: even = len8 bytes; odd = type, bits, kdf s, kdf hsel
    out["hkdf_sha256"] = script(
        imp(T_DERIVE, K32, I_KDF, kdf(0, H_SHA256)),
        [O_KDF] + kdf(0, H_SHA256) + [3] + cap(512) +
        [S_SALT] + blob8(K8) +                       # SALT
        [key_step(S_SECRET), K] +                    # SECRET from key
        [S_INFO] + blob8(K16) +                      # INFO
        [2, 32,                                      # 32 bytes, then a key
         T_RAW, 0] + kdf(0, H_SHA256))
    out["hkdf_extract"] = script(
        [O_KDF] + kdf(1, H_SHA256) + [2] + cap(256) +
        [S_SALT] + blob8(K16) +                      # SALT
        [S_SECRET] + blob8(K32) +                    # SECRET
        [1, 32])
    out["pbkdf2_password"] = script(
        imp(T_PASSWD, K8, I_KDF, kdf(5, H_SHA256)),
        [O_KDF] + kdf(5, H_SHA256) + [3] + cap(128) +
        [S_COST, 0] +                                # COST = 1 iteration
        [S_SALT] + blob8(K8) +                       # SALT
        [key_step(S_PASSWORD), K] +                  # PASSWORD from key
        [1, 16])
    out["tls12_prf"] = script(
        imp(T_DERIVE, K32, I_KDF, kdf(3, H_SHA256)),
        [O_KDF] + kdf(3, H_SHA256) + [3] + cap(256) +
        [S_SEED] + blob8(K16) +                      # SEED
        [key_step(S_SECRET), K] +                    # SECRET from key
        [S_LABEL] + blob8(K8[:4]) +                  # LABEL
        [1, 32])
    out["tls12_psk_to_ms_other_secret"] = script(
        imp(T_DERIVE, K32, I_KDF, kdf(4, H_SHA256)),
        [O_KDF] + kdf(4, H_SHA256) + [4] + cap(512) +
        [S_SEED] + blob8(K16) +                      # SEED
        [key_step(S_OTHER_SECRET), K] +              # OTHER_SECRET key
        [S_SECRET] + blob8(K16) +                    # SECRET (the PSK)
        [S_LABEL] + blob8(K8[:4]) +                  # LABEL
        [1, 48])

    # persistent key import/open + generated persistent key
    out["persistent_import_open"] = script(
        imp(T_AES, K16, I_CIPHER, [C_CTR], persistent=3),
        [O_OPEN, 3])
    out["persistent_generate_open"] = script(
        gen(T_AES, B_AES128, G_CIPHER, [C_CTR], persistent=5),
        [O_OPEN, 5])

    # copy + purge
    out["copy_purge"] = script(
        imp(T_AES, K16, I_CIPHER, [C_CTR]),
        [O_COPY, K],
        [O_PURGE, K])

    # generate_random
    out["generate_random"] = script([O_RAND, 64])

    return out


def load_rsa_der(path):
    """Extract PKCS#1 DER from a BEGIN RSA PRIVATE KEY PEM file."""
    text = open(path, "r").read()
    match = re.search(r"-----BEGIN RSA PRIVATE KEY-----"
                      r"(.*?)-+END RSA PRIVATE KEY-", text, re.S)
    if match is None:
        return None
    return base64.b64decode("".join(match.group(1).split()))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--rsa-pem", default=None,
                    help="PEM file with BEGIN RSA PRIVATE KEY (PKCS#1)")
    args = ap.parse_args()

    rsa_der = load_rsa_der(args.rsa_pem) if args.rsa_pem else None
    if args.rsa_pem and rsa_der is None:
        print("warning: no RSA PRIVATE KEY block found in %s" % args.rsa_pem,
              file=sys.stderr)

    os.makedirs(args.out, exist_ok=True)
    all_seeds = seeds(rsa_der)
    for name, blob in all_seeds.items():
        with open(os.path.join(args.out, name), "wb") as fh:
            fh.write(blob)
    print("wrote %d seeds to %s" % (len(all_seeds), args.out))


if __name__ == "__main__":
    main()
