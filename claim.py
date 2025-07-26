#!/usr/bin/env python3
import json, base64, hashlib, os, sys, asyncio, aiohttp
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from nacl.signing import SigningKey, VerifyKey

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

def derive_encryption_key(privkey_b64):
    privkey_bytes = base64.b64decode(privkey_b64)
    salt = b"octra_encrypted_balance_v2"
    return hashlib.sha256(salt + privkey_bytes).digest()[:32]

def encrypt_client_balance(balance, privkey_b64):
    key = derive_encryption_key(privkey_b64)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    plaintext = str(balance).encode()
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return "v2|" + base64.b64encode(nonce + ciphertext).decode()

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

async def get_encrypted_balance_raw(session, addr, priv):
    headers = {"X-Private-Key": priv}
    try:
        async with session.get(f"{RPC_URL}/view_encrypted_balance/{addr}", headers=headers) as res:
            data = await res.json()
            return int(data.get("encrypted_balance_raw", 0))
    except:
        return 0

async def decrypt_balance(session, addr, priv, raw_amt):
    encrypted_raw = await get_encrypted_balance_raw(session, addr, priv)
    new_raw = encrypted_raw - raw_amt
    encrypted_data = encrypt_client_balance(new_raw, priv)
    payload = {
        "address": addr,
        "amount": str(raw_amt),
        "private_key": priv,
        "encrypted_data": encrypted_data
    }
    async with session.post(f"{RPC_URL}/decrypt_balance", json=payload) as res:
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

    total_decrypt_amount = 0.0
    for tx in transfers:
        tid = tx.get("id")
        eph_key = tx.get("ephemeral_key")
        enc_data = tx.get("encrypted_data")
        if not tid or not eph_key or not enc_data:
            continue

        shared_key = derive_decryption_key(priv, eph_key)
        actual_amt = decrypt_amount(enc_data, shared_key)

        if actual_amt is None:
            print(f"{Colors.RED}✖ Failed to decrypt amount from TX {tid}{Colors.END}")
            continue

        ok = await claim_transfer(session, addr, priv, tid)
        if ok:
            total_decrypt_amount += actual_amt
            msg = f"{Colors.GREEN}✔ Claimed ID: {tid} ({actual_amt:.6f} OCT){Colors.END}"
            log_claim_result(f"{addr[:12]} | Claimed {actual_amt:.6f} OCT")
        else:
            msg = f"{Colors.RED}✖ Claim failed ID: {tid}{Colors.END}"
        print(" ", msg)
        await asyncio.sleep(2)

    if total_decrypt_amount > 0:
        raw_amt = int(total_decrypt_amount * μ)
        success = await decrypt_balance(session, addr, priv, raw_amt)
        if success:
            msg = f"{Colors.GREEN}✅ Decrypted {total_decrypt_amount:.6f} OCT for {addr[:12]}{Colors.END}"
        else:
            msg = f"{Colors.RED}❌ Decryption failed for {addr[:12]}{Colors.END}"
        print(msg)
        log_claim_result(msg)
        await asyncio.sleep(2)

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
        for i in range(1, len(addresses)):
            await process_wallet(session, i, addresses[i], privkeys[i])

if __name__ == "__main__":
    asyncio.run(main())
