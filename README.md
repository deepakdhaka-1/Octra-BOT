# 🚀 Octra Multi-Wallet Tool

![Python](https://img.shields.io/badge/Built%20With-Python-3670A0?style=for-the-badge&logo=python&logoColor=white)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)

> Automate and manage multiple Octra wallets with ease — send transactions, encrypt/decrypt balances, and perform private transfers with just a few commands.

---

## ✨ Features

- 🔁 **Multi-Wallet Execution** — Handles dozens of wallets in a single run.
- 💸 **Send Transactions** — Send random amounts to a specified address.
- 📊 **Fetch Balances** — Display balances of all wallets with indexing.
- 🔐 **Encrypt + Decrypt Balances** — Fully integrated Octra encryption logic.
- 🕵️‍♂️ **Private Transfers** — Seamlessly transfer funds between wallets privately.
- 📝 **Transaction Logs** — Records private transfer TX IDs to `record.txt`.
- ⏱ **Configurable Delays** — Set delays between transactions to avoid rate limits.

---

## 📂 File Structure
```
📦 octra-multiwallet-tool/
├── accounts.txt               # Your private keys (base64)
├── address.txt                # Wallet addresses (oct...)
├── record.txt                 # Logs private transfer TXs
├───main.py # Main tool
└──claim.py # 2nd Main tool    # Execute Claim and decrypt from record.txt
```
## `main.py`
### 1️⃣ Send Tx
- 🧾 Prompt: `Recipient Address` + `Amount`  
- 🚀 Executes a transaction from **all wallets**, dropping the random amount between minimum and maximum amount provided.

---

### 2️⃣ Balance
- 📡 Fetches and displays the **real-time balance** of each wallet  
- ✅ Uses `GET /balance/{address}` RPC endpoint

---

### 3️⃣ Multi Send
- ⚙️ Prompt: `Min Amount`, `Max Amount`, `Delay Between`  
- 🔁 Sends **random amounts** from each wallet to a **random order of other wallets**  
- 📦 Respects balance and nonce tracking

---

### 4️⃣ Encrypt + Private Transfer + Decrypt
- 🔐 Prompts for:  
  - Amount to Encrypt  
  - Amount to Private Transfer  
  - Amount to Decrypt  
- ⚙️ Executes in order:  
  `Encrypt ➝ 120s ➝ Private Transfer ➝ 120s ➝ Decrypt ➝ 120s`  
- 📁 Logs all private transfer TXs into `record.txt`

## `claim.py` – Passive Claimer
- 🔍 Checks for pending private transfers  
- ✅ Automatically claims them  
- 🔓 Immediately decrypts the transferred balance  
- 🔁 Runs across all wallets in `address.txt` + `accounts.txt`

## Main Commands ~
```
git clone https://github.com/deepakdhaka-1/Octra-BOT
cd Octra-BOT
```
```
pip install -r requirements.txt
```
## Add credentials in `accounts.txt` and `address.txt`
```
python3 main.py
```
Once Done then run ~
```
python3 claim.py
```
During Claim Decryption will be failed , that is not any issue. As we already done the decryption.
Important thing is our interaction is getting counted.
