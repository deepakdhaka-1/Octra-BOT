#!/usr/bin/env python3
import json, base64, hashlib, time, sys, re, os, random, asyncio, aiohttp, threading
from datetime import datetime
import nacl.signing
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import ssl

# Constants
μ = 1_000_000
b58 = re.compile(r"^oct[1-9A-HJ-NP-Za-km-z]{44}$")
OCTRASCAN_URL = "https://octrascan.io/tx/"
DELAY_BETWEEN_OPERATIONS = 120  # 2 minutes between operations

# Color formatting
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

# Global variables
session = None
accounts = []
addresses = []
current_rpc = "https://octra.network"  # Fixed RPC as requested
record_file = "record.txt"

def derive_encryption_key(privkey_b64):
    privkey_bytes = base64.b64decode(privkey_b64)
    salt = b"octra_encrypted_balance_v2"
    return hashlib.sha256(salt + privkey_bytes).digest()[:32]

def encrypt_client_balance(balance, privkey_b64):
    key = derive_encryption_key(privkey_b64)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    plaintext = str(balance).encode()
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return "v2|" + base64.b64encode(nonce + ciphertext).decode()

def derive_shared_secret_for_claim(my_privkey_b64, ephemeral_pubkey_b64):
    sk = nacl.signing.SigningKey(base64.b64decode(my_privkey_b64))
    my_pubkey_bytes = sk.verify_key.encode()
    eph_pub_bytes = base64.b64decode(ephemeral_pubkey_b64)
    
    if eph_pub_bytes < my_pubkey_bytes:
        smaller, larger = eph_pub_bytes, my_pubkey_bytes
    else:
        smaller, larger = my_pubkey_bytes, eph_pub_bytes
    
    combined = smaller + larger
    round1 = hashlib.sha256(combined).digest()
    round2 = hashlib.sha256(round1 + b"OCTRA_SYMMETRIC_V1").digest()
    return round2[:32]

async def req(account, method, path, data=None, timeout=30):
    global session
    url = f"{account['rpc']}{path}"
    try:
        kwargs = {'timeout': aiohttp.ClientTimeout(total=timeout)}
        if method == 'POST' and data:
            kwargs['json'] = data
            
        async with session.request(method, url, **kwargs) as resp:
            text = await resp.text()
            try:
                j = json.loads(text) if text.strip() else None
            except:
                j = None
            return resp.status, text, j
    except asyncio.TimeoutError:
        return 0, "timeout", None
    except Exception as e:
        return 0, str(e), None

async def req_private(account, path, method='GET', data=None):
    headers = {"X-Private-Key": account['priv']}
    url = f"{account['rpc']}{path}"
    try:
        kwargs = {'headers': headers, 'timeout': aiohttp.ClientTimeout(total=60)}
        if method == 'POST' and data:
            kwargs['json'] = data
            
        async with session.request(method, url, **kwargs) as resp:
            text = await resp.text()
            if resp.status == 200:
                try:
                    return True, json.loads(text) if text.strip() else {}
                except:
                    return False, {"error": "Invalid JSON response"}
            else:
                return False, {"error": f"HTTP {resp.status}"}
    except Exception as e:
        return False, {"error": str(e)}

async def get_balance_and_nonce(account):
    s, t, j = await req(account, 'GET', f'/balance/{account["addr"]}')
    if s == 200 and j:
        return int(j.get('nonce', 0)), float(j.get('balance', 0))
    return None, None

async def get_encrypted_balance(account):
    ok, result = await req_private(account, f"/view_encrypted_balance/{account['addr']}")
    if ok:
        try:
            return {
                "public": float(result.get("public_balance", "0").split()[0]),
                "public_raw": int(result.get("public_balance_raw", "0")),
                "encrypted": float(result.get("encrypted_balance", "0").split()[0]),
                "encrypted_raw": int(result.get("encrypted_balance_raw", "0")),
                "total": float(result.get("total_balance", "0").split()[0])
            }
        except:
            return None
    return None

async def encrypt_balance(account, amount):
    enc_data = await get_encrypted_balance(account)
    if not enc_data:
        return False, {"error": "Cannot get balance"}
    
    current_encrypted_raw = enc_data['encrypted_raw']
    new_encrypted_raw = current_encrypted_raw + int(amount * μ)
    encrypted_value = encrypt_client_balance(new_encrypted_raw, account['priv'])
    
    data = {
        "address": account['addr'],
        "amount": str(int(amount * μ)),
        "private_key": account['priv'],
        "encrypted_data": encrypted_value
    }
    
    s, t, j = await req(account, 'POST', '/encrypt_balance', data)
    if s == 200:
        return True, j
    return False, {"error": j.get("error", t) if j else t}

async def decrypt_balance(account, amount):
    enc_data = await get_encrypted_balance(account)
    if not enc_data:
        return False, {"error": "Cannot get balance"}
    
    current_encrypted_raw = enc_data['encrypted_raw']
    if current_encrypted_raw < int(amount * μ):
        return False, {"error": "Insufficient encrypted balance"}
    
    new_encrypted_raw = current_encrypted_raw - int(amount * μ)
    encrypted_value = encrypt_client_balance(new_encrypted_raw, account['priv'])
    
    data = {
        "address": account['addr'],
        "amount": str(int(amount * μ)),
        "private_key": account['priv'],
        "encrypted_data": encrypted_value
    }
    
    s, t, j = await req(account, 'POST', '/decrypt_balance', data)
    if s == 200:
        return True, j
    return False, {"error": j.get("error", t) if j else t}

async def get_public_key(account, address):
    s, t, j = await req(account, 'GET', f'/public_key/{address}')
    if s == 200:
        return j.get("public_key")
    return None

async def create_private_transfer(sender, recipient_addr, amount):
    # Get recipient's public key
    pub_key = await get_public_key(sender, recipient_addr)
    if not pub_key:
        return False, {"error": "Failed to get recipient public key"}
    
    data = {
        "from": sender['addr'],
        "to": recipient_addr,
        "amount": str(int(amount * μ)),
        "from_private_key": sender['priv'],
        "to_public_key": pub_key
    }
    
    s, t, j = await req(sender, 'POST', '/private_transfer', data)
    if s == 200:
        tx_hash = j.get('tx_hash', '')
        # Only record private transfer hashes
        record_transaction(tx_hash)
        return True, j
    return False, {"error": j.get("error", t) if j else t}

async def send_transaction(sender, recipient, amount, nonce_offset=1):
    nonce, balance = await get_balance_and_nonce(sender)
    if nonce is None or balance is None:
        return False, "Failed to get balance/nonce"
    
    if balance < amount:
        return False, f"Insufficient balance ({balance:.6f} < {amount:.6f})"
    
    # Build transaction
    tx = {
        "from": sender['addr'],
        "to_": recipient,
        "amount": str(int(amount * μ)),
        "nonce": nonce + nonce_offset,
        "ou": "1" if amount < 1000 else "3",
        "timestamp": time.time()
    }
    bl = json.dumps({k: v for k, v in tx.items()}, separators=(",", ":"))
    sk_signing = nacl.signing.SigningKey(base64.b64decode(sender['priv']))
    pub_key = base64.b64encode(sk_signing.verify_key.encode()).decode()
    sig = base64.b64encode(sk_signing.sign(bl.encode()).signature).decode()
    tx.update(signature=sig, public_key=pub_key)
    
    # Send transaction
    s, t, j = await req(sender, 'POST', '/send-tx', tx)
    if s == 200:
        tx_hash = j.get('tx_hash') if j else t.split()[-1] if t.lower().startswith('ok') else ''
        return True, tx_hash
    return False, json.dumps(j) if j else t

def load_accounts():
    global accounts, addresses, current_rpc
    try:
        with open('accounts.txt', 'r') as f:
            priv_keys = [line.strip() for line in f if line.strip()]
        
        with open('address.txt', 'r') as f:
            addresses = [line.strip() for line in f if line.strip()]
        
        if len(priv_keys) != len(addresses):
            print(f"{Colors.RED}Error: accounts.txt and address.txt have different line counts{Colors.END}")
            return False
        
        accounts = []
        for priv, addr in zip(priv_keys, addresses):
            accounts.append({
                'priv': priv,
                'addr': addr,
                'rpc': current_rpc,
                'last_nonce': None
            })
        return True
    except Exception as e:
        print(f"{Colors.RED}Error loading accounts: {e}{Colors.END}")
        return False

def clear_record_file():
    try:
        open(record_file, 'w').close()
    except:
        print(f"{Colors.RED}Failed to clear record file{Colors.END}")

def record_transaction(tx_hash):
    """Simplified to only record transaction hashes"""
    try:
        with open(record_file, 'a') as f:
            f.write(f"{tx_hash}\n")
    except Exception as e:
        print(f"{Colors.RED}Failed to record transaction: {e}{Colors.END}")

async def get_and_update_nonce(account):
    """Get current nonce and update account state"""
    nonce, _ = await get_balance_and_nonce(account)
    if nonce is not None:
        account['last_nonce'] = nonce
    return nonce

async def wait_for_nonce_update(account, initial_nonce, timeout=120):
    """Wait until nonce increases or timeout reached"""
    start_time = time.time()
    while time.time() - start_time < timeout:
        current_nonce, _ = await get_balance_and_nonce(account)
        if current_nonce is not None and current_nonce > initial_nonce:
            account['last_nonce'] = current_nonce
            return True
        await asyncio.sleep(5)
    return False

async def send_tx_all_wallets(min_amount, max_amount):
    for idx, account in enumerate(accounts):
        print(f"\n{Colors.BOLD}Processing Wallet {idx+1}: {account['addr'][:12]}...{Colors.END}")
        nonce, balance = await get_balance_and_nonce(account)
        if balance is None:
            print(f"  {Colors.RED}Failed to fetch balance{Colors.END}")
            continue
            
        print(f"  {Colors.CYAN}Balance: {balance:.6f} OCT, Nonce: {nonce}{Colors.END}")
        
        for recipient in addresses:
            amount = random.uniform(min_amount, max_amount)
            fee = 0.001 if amount < 1000 else 0.003
            if balance < amount + fee:
                print(f"  {Colors.YELLOW}Insufficient balance for {recipient[:12]}... (needed: {amount+fee:.6f}){Colors.END}")
                continue
                
            print(f"  {Colors.BLUE}Sending {amount:.6f} OCT to {recipient[:12]}...{Colors.END}")
            success, tx_hash = await send_transaction(account, recipient, amount)
            if success:
                print(f"  {Colors.GREEN}Success! TX Hash: {tx_hash}{Colors.END}")
                print(f"  {Colors.CYAN}Explorer: {OCTRASCAN_URL}{tx_hash}{Colors.END}")
                balance -= (amount + fee)
                # Update nonce after successful transaction
                await wait_for_nonce_update(account, nonce)
            else:
                print(f"  {Colors.RED}Failed: {tx_hash}{Colors.END}")

async def multi_send(min_amount, max_amount, min_delay, max_delay):
    for idx, account in enumerate(accounts):
        print(f"\n{Colors.BOLD}Processing Wallet {idx+1}: {account['addr'][:12]}...{Colors.END}")
        nonce, balance = await get_balance_and_nonce(account)
        if balance is None:
            print(f"  {Colors.RED}Failed to fetch balance{Colors.END}")
            continue
            
        print(f"  {Colors.CYAN}Balance: {balance:.6f} OCT, Nonce: {nonce}{Colors.END}")
        
        for recipient in addresses:
            amount = random.uniform(min_amount, max_amount)
            fee = 0.001 if amount < 1000 else 0.003
            if balance < amount + fee:
                print(f"  {Colors.YELLOW}Insufficient balance for {recipient[:12]}...{Colors.END}")
                continue
                
            print(f"  {Colors.BLUE}Sending {amount:.6f} OCT to {recipient[:12]}...{Colors.END}")
            success, tx_hash = await send_transaction(account, recipient, amount)
            if success:
                print(f"  {Colors.GREEN}Success! TX Hash: {tx_hash}{Colors.END}")
                print(f"  {Colors.CYAN}Explorer: {OCTRASCAN_URL}{tx_hash}{Colors.END}")
                balance -= (amount + fee)
                # Update nonce after successful transaction
                await wait_for_nonce_update(account, nonce)
            else:
                print(f"  {Colors.RED}Failed: {tx_hash}{Colors.END}")
            
            delay = random.uniform(min_delay, max_delay)
            print(f"  {Colors.YELLOW}Waiting {delay:.1f} seconds...{Colors.END}")
            await asyncio.sleep(delay)

async def private_operations(encrypt_amt, decrypt_amt, transfer_amt):
    if len(accounts) < 2:
        print(f"{Colors.RED}Need at least 2 wallets for private operations{Colors.END}")
        return
    
    # Clear record file at start
    clear_record_file()
    
    for i in range(len(accounts) - 1):
        sender = accounts[i]
        receiver = accounts[i + 1]
        
        print(f"\n{Colors.BOLD}Processing Wallet {i+1}: {sender['addr'][:12]}...{Colors.END}")
        initial_nonce, balance = await get_balance_and_nonce(sender)
        if balance is None:
            print(f"  {Colors.RED}Failed to fetch balance{Colors.END}")
            continue
            
        print(f"  {Colors.CYAN}Balance: {balance:.6f} OCT, Nonce: {initial_nonce}{Colors.END}")
        
        # Step 1: Encrypt
        print(f"  {Colors.BLUE}Encrypting {encrypt_amt:.6f} OCT...{Colors.END}")
        success, result = await encrypt_balance(sender, encrypt_amt)
        if success:
            tx_hash = result.get('tx_hash', '')
            print(f"  {Colors.GREEN}Encryption successful! TX Hash: {tx_hash}{Colors.END}")
            print(f"  {Colors.CYAN}Explorer: {OCTRASCAN_URL}{tx_hash}{Colors.END}")
        else:
            print(f"  {Colors.RED}Encryption failed: {result.get('error', 'Unknown error')}{Colors.END}")
        
        # Wait for encryption to complete and nonce to update
        print(f"  {Colors.YELLOW}Waiting {DELAY_BETWEEN_OPERATIONS} seconds for confirmation...{Colors.END}")
        await asyncio.sleep(DELAY_BETWEEN_OPERATIONS)
        await wait_for_nonce_update(sender, initial_nonce)
        
        # Step 2: Private Transfer
        print(f"  {Colors.BLUE}Privately transferring {transfer_amt:.6f} OCT to next wallet...{Colors.END}")
        success, result = await create_private_transfer(sender, receiver['addr'], transfer_amt)
        if success:
            tx_hash = result.get('tx_hash', '')
            print(f"  {Colors.GREEN}Private transfer successful! TX Hash: {tx_hash}{Colors.END}")
            print(f"  {Colors.CYAN}Explorer: {OCTRASCAN_URL}{tx_hash}{Colors.END}")
        else:
            print(f"  {Colors.RED}Private transfer failed: {result.get('error', 'Unknown error')}{Colors.END}")
        
        # Wait for private transfer to complete
        print(f"  {Colors.YELLOW}Waiting {DELAY_BETWEEN_OPERATIONS} seconds for confirmation...{Colors.END}")
        await asyncio.sleep(DELAY_BETWEEN_OPERATIONS)
        
        # Step 3: Decrypt
        print(f"  {Colors.BLUE}Decrypting {decrypt_amt:.6f} OCT...{Colors.END}")
        success, result = await decrypt_balance(sender, decrypt_amt)
        if success:
            tx_hash = result.get('tx_hash', '')
            print(f"  {Colors.GREEN}Decryption successful! TX Hash: {tx_hash}{Colors.END}")
            print(f"  {Colors.CYAN}Explorer: {OCTRASCAN_URL}{tx_hash}{Colors.END}")
        else:
            print(f"  {Colors.RED}Decryption failed: {result.get('error', 'Unknown error')}{Colors.END}")
        
        # Final wait before next wallet
        if i < len(accounts) - 2:
            print(f"  {Colors.YELLOW}Waiting {DELAY_BETWEEN_OPERATIONS} seconds before next wallet...{Colors.END}")
            await asyncio.sleep(DELAY_BETWEEN_OPERATIONS)

async def show_balances():
    print(f"\n{Colors.HEADER}{'Wallet Balances':^60}{Colors.END}")
    print(f"{Colors.BOLD}{'#':<4}{'Address':<20}{'Balance (OCT)':>15}{'Nonce':>10}{Colors.END}")
    print(f"{Colors.YELLOW}{'-'*60}{Colors.END}")
    
    for i, account in enumerate(accounts):
        nonce, balance = await get_balance_and_nonce(account)
        if balance is not None:
            color = Colors.GREEN if balance > 0 else Colors.YELLOW
            print(f"{color}[{i}]{Colors.END} {account['addr'][:18]} {balance:>14.6f} {nonce:>10}")
        else:
            print(f"{Colors.RED}[{i}]{Colors.END} {account['addr'][:18]} {'Unavailable':>15} {'N/A':>10}")

async def main_menu():
    global session
    
    # Load accounts
    if not load_accounts():
        return
    
    # Create HTTP session
    ssl_context = ssl.create_default_context()
    connector = aiohttp.TCPConnector(ssl=ssl_context)
    session = aiohttp.ClientSession(connector=connector)
    
    while True:
        print(f"\n{Colors.HEADER}{'==== OCTRA MULTI-WALLET TOOL ====':^60}{Colors.END}")
        print(f"{Colors.BOLD}[1]{Colors.END} Send tx to all addresses")
        print(f"{Colors.BOLD}[2]{Colors.END} Show balances")
        print(f"{Colors.BOLD}[3]{Colors.END} Multi-send with delays")
        print(f"{Colors.BOLD}[4]{Colors.END} Encrypt + Private Transfer + Decrypt")
        print(f"{Colors.BOLD}[5]{Colors.END} Exit")
        
        choice = input(f"{Colors.BOLD}Select option: {Colors.END}").strip()
        
        if choice == '1':
            min_amt = float(input(f"{Colors.BOLD}Minimum amount: {Colors.END}"))
            max_amt = float(input(f"{Colors.BOLD}Maximum amount: {Colors.END}"))
            await send_tx_all_wallets(min_amt, max_amt)
            
        elif choice == '2':
            await show_balances()
            
        elif choice == '3':
            min_amt = float(input(f"{Colors.BOLD}Minimum amount: {Colors.END}"))
            max_amt = float(input(f"{Colors.BOLD}Maximum amount: {Colors.END}"))
            min_delay = float(input(f"{Colors.BOLD}Minimum delay (sec): {Colors.END}"))
            max_delay = float(input(f"{Colors.BOLD}Maximum delay (sec): {Colors.END}"))
            await multi_send(min_amt, max_amt, min_delay, max_delay)
            
        elif choice == '4':
            encrypt_amt = float(input(f"{Colors.BOLD}Encrypt amount: {Colors.END}"))
            transfer_amt = float(input(f"{Colors.BOLD}Private transfer amount: {Colors.END}"))
            decrypt_amt = float(input(f"{Colors.BOLD}Decrypt amount: {Colors.END}"))
            await private_operations(encrypt_amt, decrypt_amt, transfer_amt)
            
        elif choice == '5':
            break
            
    await session.close()

if __name__ == "__main__":
    try:
        asyncio.run(main_menu())
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Exiting...{Colors.END}")
        if session:
            asyncio.run(session.close())
    finally:
        print(f"{Colors.END}")
