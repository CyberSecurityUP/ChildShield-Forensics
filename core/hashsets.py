# core/hashsets.py
import os, math, json, hashlib
from typing import Optional, Iterable, Tuple
from PIL import Image
import imagehash

class BloomSet:
    def __init__(self, size_bits=1_000_000, hashes=7):
        self.size = size_bits
        self.hashes = hashes
        self.bits = bytearray(size_bits // 8 + 1)

    def _indexes(self, b: bytes):
        h1 = int(hashlib.sha256(b).hexdigest(), 16)
        h2 = int(hashlib.md5(b).hexdigest(), 16)
        for i in range(self.hashes):
            yield (h1 + i * h2) % self.size

    def add(self, b: bytes):
        for idx in self._indexes(b):
            self.bits[idx // 8] |= (1 << (idx % 8))

    def __contains__(self, b: bytes):
        return all(self.bits[idx // 8] & (1 << (idx % 8)) for idx in self._indexes(b))

class HashDB:
    """
    Stores SHA-256 and perceptual hashes only (no media).
    """
    def __init__(self):
        self.sha256 = BloomSet()
        self.phash = {}  # map hex->True for exact; near match via hamming

    def import_sha256_list(self, iterable: Iterable[str]):
        for h in iterable:
            h = h.strip().lower()
            if len(h) == 64:
                self.sha256.add(bytes.fromhex(h))

    def import_phash_list(self, iterable: Iterable[str]):
        for h in iterable:
            h = h.strip().lower()
            if len(h) in (16, 32):  # imagehash length as hex
                self.phash[h] = True

    @staticmethod
    def img_phash(path: str) -> str:
        with Image.open(path) as im:
            return str(imagehash.phash(im))

    @staticmethod
    def hamming(a: str, b: str) -> int:
        return bin(int(a, 16) ^ int(b, 16)).count("1")

    def match_sha256(self, h: str) -> bool:
        try:
            return bytes.fromhex(h) in self.sha256
        except Exception:
            return False

    def match_phash(self, ph: str, max_dist=6) -> Tuple[bool,int]:
        if ph in self.phash:
            return True, 0
        # near match
        best = 128
        for k in self.phash.keys():
            d = self.hamming(ph, k)
            if d < best: best = d
            if d <= max_dist: return True, d
        return False, best
