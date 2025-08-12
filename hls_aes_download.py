#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import requests
import m3u8
from urllib.parse import urljoin
from Crypto.Cipher import AES

# ===== 設定部分 =====
M3U8_URL = "https://ex.com/ex.m3u8"  # 実際のm3u8 URLに置き換え

# ブラウザの開発者ツール → ネットワーク → m3u8やtsのリクエストからコピー
CUSTOM_HEADERS = {
    "User-Agent": "ex
    "Referer": "https://ex.com/0/",
    # Cookieが必要ならここに貼り付け
    "Cookie": "sessionid=xxxxx; other_cookie=yyyyy"
}

OUT_DIR = "hls_download"
OUT_TS = os.path.join(OUT_DIR, "output.ts")
# ====================

SESSION = requests.Session()
SESSION.headers.update(CUSTOM_HEADERS)


def ensure_dir(p):
    if not os.path.exists(p):
        os.makedirs(p, exist_ok=True)


def fetch_bytes(url):
    r = SESSION.get(url, stream=True, timeout=30)
    r.raise_for_status()
    return r.content


def hex_iv_to_bytes(iv_spec, seq_num):
    if iv_spec:
        if iv_spec.startswith("0x") or iv_spec.startswith("0X"):
            hexstr = iv_spec[2:]
        else:
            hexstr = iv_spec
        b = bytes.fromhex(hexstr)
        if len(b) < 16:
            b = (b"\x00" * (16 - len(b))) + b
        elif len(b) > 16:
            b = b[-16:]
        return b
    else:
        return seq_num.to_bytes(16, byteorder='big')


def main():
    ensure_dir(OUT_DIR)
    print("Loading playlist:", M3U8_URL)
    playlist = m3u8.load(M3U8_URL, headers=CUSTOM_HEADERS)

    if playlist.is_variant:
        variant = playlist.playlists[0]
        playlist = m3u8.load(urljoin(M3U8_URL, variant.uri), headers=CUSTOM_HEADERS)
        print("Variant selected:", variant.uri)

    key_obj = None
    if playlist.keys:
        for k in playlist.keys:
            if k and k.method and k.method.upper() != "NONE":
                key_obj = k
                break

    key_bytes = None
    if key_obj:
        key_uri = key_obj.absolute_uri or urljoin(M3U8_URL, key_obj.uri)
        print("Detected encryption method:", key_obj.method, " key URI:", key_uri)

        if key_obj.method.upper() != "AES-128":
            print("Unsupported encryption method:", key_obj.method)
            sys.exit(1)

        key_bytes = fetch_bytes(key_uri)
        if len(key_bytes) != 16:
            raise RuntimeError("Key length error (expected 16 bytes).")

    segments = playlist.segments
    if not segments:
        print("No segments found in playlist.")
        sys.exit(1)

    print("Found", len(segments), "segments. Downloading...")

    with open(OUT_TS, "wb") as out_f:
        for idx, seg in enumerate(segments):
            seg_url = seg.absolute_uri or urljoin(M3U8_URL, seg.uri)
            print(f"[{idx+1}/{len(segments)}] {seg_url}")
            data = fetch_bytes(seg_url)

            if key_bytes:
                if key_obj.iv:
                    iv = hex_iv_to_bytes(key_obj.iv, idx)
                else:
                    seq_start = getattr(playlist, "media_sequence", 0) or 0
                    iv = hex_iv_to_bytes(None, seq_start + idx)
                cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
                dec = cipher.decrypt(data)
                out_f.write(dec)
            else:
                out_f.write(data)

    print("Done:", OUT_TS)


if __name__ == "__main__":
    main()
