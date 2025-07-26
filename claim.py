#!/usr/bin/env python3
import json, base64, hashlib, os, sys, asyncio, aiohttp
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from nacl.signing import SigningKey

μ = 1_000_000
RPC_URL = "https://octra.network"
LOG_FILE = "claimed_log.txt"

class Colors:
    GREEN = '\033[92m'
    CYAN = '\033[96m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BOLD = '\033[1m'
    END = '\033[0m'

def derive_decryption_key(my_priv_b64, ephemeral_pub_b64):
    my_sk = SigningKey(base64.b64decode(my_priv_b64))
    my_pub = my_sk.verify_key.encode()
    eph_pub = base64.b64decode(ephemeral_pub_b64)
    smaller, larger = sorted([my_pub, eph_pub])
    shared = hashlib.sha256(smaller + larger).digest()
    final_key = hashlib.sha256(shared + b"OCTRA_SYMMETRIC_V1").digest()
    return final_key[:32]

def decrypt_amount(encrypted_data_b64, shared_key):
    if encrypted_data_b64.startswith("v2|"):
        encrypted_data_b64 = encrypted_data_b64[3:]
    raw = base64.b64decode(encrypted_data_b64)
    nonce = raw[:12]
    ciphertext = raw[12:]
    aesgcm = AESGCM(shared_key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return float(plaintext.decode())
    except:
        return None

async def get_pending_transfers(session, addr, priv):
    headers = {"X-Private-Key": priv}
    try:
        async with session.get(f"{RPC_URL}/pending_private_transfers?address={addr}", headers=headers) as res:
            text = await res.text()
            try:
                data = json.loads(text)
                return data.get("pending_transfers", [])
            except json.JSONDecodeError:
                print(f"{Colors.RED}Invalid JSON for {addr[:12]}: {text}{Colors.END}")
                return []
    except Exception as e:
        print(f"{Colors.RED}Error fetching for {addr[:12]}: {e}{Colors.END}")
        return []

async def claim_transfer(session, addr, priv, transfer_id):
    headers = {"X-Private-Key": priv}
    payload = {
        "recipient_address": addr,
        "private_key": priv,
        "transfer_id": transfer_id
    }
    async with session.post(f"{RPC_URL}/claim_private_transfer", json=payload, headers=headers) as res:
        return res.status == 200

def log_claim_result(line: str):
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

async def process_wallet(session, idx, addr, priv):
    print(f"\n{Colors.BOLD}[{idx}] Processing {addr[:12]}...{Colors.END}")
    transfers = await get_pending_transfers(session, addr, priv)

    if not transfers:
        msg = f"{Colors.YELLOW}{addr[:12]}... | No pending transfers{Colors.END}"
        print(msg)
        log_claim_result(msg)
        return

    for tx in transfers:
        tid = tx.get("id")
        eph_key = tx.get("ephemeral_key")
        enc_data = tx.get("encrypted_data")
        if not tid or not eph_key or not enc_data:
            continue

        shared_key = derive_decryption_key(priv, eph_key)
        actual_amt = decrypt_amount(enc_data, shared_key)

        ok = await claim_transfer(session, addr, priv, tid)
        if ok:
            msg = f"{Colors.GREEN}✔ Claimed ID: {tid} ({actual_amt:.6f} OCT){Colors.END}"
            log_claim_result(f"{addr[:12]} | Claimed {actual_amt:.6f} OCT")
        else:
            msg = f"{Colors.RED}✖ Claim failed ID: {tid}{Colors.END}"
        print(" ", msg)
        await asyncio.sleep(150)  # delay between each transfer claim

async def main():
    try:
        with open("address.txt") as f1, open("accounts.txt") as f2:
            addresses = [x.strip() for x in f1 if x.strip()]
            privkeys = [x.strip() for x in f2 if x.strip()]
    except Exception as e:
        print(f"{Colors.RED}File load error: {e}{Colors.END}")
        return

    if len(addresses) != len(privkeys):
        print(f"{Colors.RED}Mismatch in address/private key count{Colors.END}")
        return

    open(LOG_FILE, "w").close()

    async with aiohttp.ClientSession() as session:
        for i in range(len(addresses)):
            await process_wallet(session, i+1, addresses[i], privkeys[i])
            await asyncio.sleep(60)  # 1 minute delay between wallets

if __name__ == "__main__":
    asyncio.run(main())

