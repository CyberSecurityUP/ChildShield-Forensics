import re
import hashlib

BTC_REGEX = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
BECH32_REGEX = re.compile(r"\bbc1[ac-hj-np-z02-9]{11,71}\b", re.IGNORECASE)
ETH_REGEX = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
# Monero: modern addresses are 95 chars base58-like; simplified regex:
XMR_REGEX = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{92}\b")

# Base58 alphabet
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def base58_decode(s):
    num = 0
    for c in s:
        num = num * 58 + BASE58_ALPHABET.index(c)
    return num.to_bytes((num.bit_length() + 7)//8, 'big') if num>0 else b'\x00'

def validate_btc_base58(address: str) -> bool:
    try:
        decoded = base58_decode(address)
        if len(decoded) < 4:
            return False
        checksum = decoded[-4:]
        vh160 = decoded[:-4]
        h = hashlib.sha256(hashlib.sha256(vh160).digest()).digest()
        return checksum == h[:4]
    except Exception:
        return False

# Placeholder bech32 and EIP-55 checks — use libraries in production
def validate_eth_checksum(addr: str) -> bool:
    # crude: accept lowercase (non-checksum) and basic structure; real impl: EIP-55
    if not ETH_REGEX.match(addr):
        return False
    # TODO: implement EIP-55 verification; return True for now if matching regex
    return True

def find_wallets_in_text(text: str):
    matches = []
    for r in BTC_REGEX.findall(text):
        if validate_btc_base58(r):
            matches.append(r)
    for r in BECH32_REGEX.findall(text):
        matches.append(r)
    for r in ETH_REGEX.findall(text):
        if validate_eth_checksum(r):
            matches.append(r)
    for r in XMR_REGEX.findall(text):
        matches.append(r)
    return matches

def find_wallets_in_image_text(image_path: str):
    # Placeholder: In production, run OCR (Tesseract) and then find_wallets_in_text on result
    return []
