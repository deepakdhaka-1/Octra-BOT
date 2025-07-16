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

## Usage
==== OCTRA MULTI-WALLET TOOL ====
[1] Send tx
[2] Balance
[3] Multi Send
[4] Encrypt + Private Transfer + Decrypt
[5] Exit
