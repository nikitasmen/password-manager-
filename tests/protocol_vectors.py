#!/usr/bin/env python3
"""Deterministic test vectors for docs/PROTOCOL.md, from the Python reference implementation.

  python3 tests/protocol_vectors.py            # print vectors as JSON (C++ tests read this)
  python3 tests/protocol_vectors.py --check    # self-check round trips, tamper detection, merge rule
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "clients", "python"))
import vaultproto as vp  # noqa: E402

PASSWORD = "correct horse battery staple"
SALT = bytes(range(16))
VAULT_KEY = bytes(range(32, 64))
VAULT_ID = "00112233445566778899aabbccddeeff"
NONCE = bytes(range(100, 112))
ITER = 1000  # low so tests are fast; real vaults use 600000
UPDATED = 1759075200000


def vectors():
    out = {"password": PASSWORD, "vault_key_hex": VAULT_KEY.hex(), "nonce_hex": NONCE.hex(), "updated": UPDATED}
    for alg in vp.CIPHERS:
        meta, _ = vp.new_meta(PASSWORD, alg, ITER, VAULT_KEY, SALT, VAULT_ID, NONCE)
        entry = vp.seal_entry(VAULT_KEY, alg, "GitHub", "nik", "s3cret", UPDATED, NONCE)
        out[alg] = {"kek_hex": vp.kek(PASSWORD, meta).hex(), "meta": meta, "entry": entry}
    out["entry_id_github"] = vp.entry_id(VAULT_KEY, "GitHub")
    return out


def check():
    v = vectors()
    for alg in vp.CIPHERS:
        meta, entry = v[alg]["meta"], v[alg]["entry"]
        assert vp.unlock(PASSWORD, meta) == VAULT_KEY
        try:
            vp.unlock("wrong", meta)
            raise AssertionError("wrong password accepted")
        except vp.WrongPassword:
            pass
        assert vp.open_entry(VAULT_KEY, entry) == {"platform": "GitHub", "username": "nik", "password": "s3cret"}
        swapped = dict(entry, id="ff" * 16)  # AAD binds the blob to its id
        try:
            vp.open_entry(VAULT_KEY, swapped)
            raise AssertionError("blob accepted under another id")
        except Exception as e:
            assert type(e).__name__ == "InvalidTag", e
    assert vp.entry_id(VAULT_KEY, "github") == vp.entry_id(VAULT_KEY, "GitHub")
    a = {"updated": 2, "data": "a"}
    assert vp.newer(a, {"updated": 1, "data": "z"}) and not vp.newer({"updated": 1, "data": "z"}, a)
    assert vp.newer({"updated": 2, "data": "b"}, a) and not vp.newer(a, a)
    print("protocol vectors: ok")


if __name__ == "__main__":
    check() if "--check" in sys.argv else print(json.dumps(vectors(), indent=2))
