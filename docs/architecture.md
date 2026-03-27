# AEGIS Offline Payments — Architecture

## Overview

The AEGIS Offline Payment system enables **peer-to-peer payments using Digital Euro tokens** without requiring internet connectivity. Payments are secured by cryptographic operations performed entirely inside a **Secure Element (SE)** chip, typically embedded in a smartphone's NFC controller.

## System Components

```
┌─────────────────────────────────────────────────────────────┐
│                     AEGIS Offline Payments                   │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │  SE Applet   │    │  Host SDK    │    │  Simulator   │  │
│  │  (Java Card) │    │  (Python)    │    │  (Python)    │  │
│  │              │    │              │    │              │  │
│  │ • Wallet     │◄──►│ • APDU Layer │◄──►│ • SE Emu     │  │
│  │ • Crypto     │    │ • SE Comm    │    │ • ECDSA      │  │
│  │ • Signing    │    │ • Payment    │    │ • State      │  │
│  │ • PIN        │    │ • Sync       │    │              │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│         │                    │                    │          │
│         ▼                    ▼                    ▼          │
│  ┌──────────────────────────────────────────────────────┐  │
│  │                 NFC / ISO 7816 APDU                   │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │           AEGIS Settlement Ledger (Online)            │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Component Details

### 1. Secure Element Applet (`se-applet/`)

**Language:** Java Card 3.0  
**Runs on:** Embedded SE chip (e.g., NXP JCOP, Infineon SLE78)

The applet is the **trust anchor** of the system. It:

- Stores the wallet private key (ECDSA secp256k1) — **never exported**
- Maintains an atomic balance (euro-cents) with overflow protection
- Maintains a monotonic transaction counter (anti-replay)
- Signs payment receipts with the private key
- Verifies incoming payment receipts from peer SEs
- Enforces per-transaction and balance limits
- Protects privileged operations with a 6-digit PIN

**Key classes:**
| Class | Responsibility |
|---|---|
| `AegisPaymentApplet` | APDU dispatcher, lifecycle |
| `TransactionManager` | Balance, counter, receipts, atomic state |
| `CryptoEngine` | ECDSA keygen, sign, verify, SHA-256 |
| `Constants` | Protocol constants, APDU codes, limits |

### 2. Host SDK (`host-sdk/`)

**Language:** Python 3.9+  
**Runs on:** Smartphone or terminal host processor

The SDK provides:

- **APDU layer** (`apdu.py`): Builds and parses ISO 7816-4 commands
- **SE communication** (`secure_element.py`): Abstract transport + high-level API
- **Payment protocol** (`payment.py`): Orchestrates the P2P flow
- **Transaction model** (`transaction.py`): Receipt parsing and serialization
- **Sync module** (`sync.py`): Online reconciliation when connectivity returns
- **Exceptions** (`exceptions.py`): Typed error hierarchy

### 3. Simulator (`simulator/`)

**Language:** Python 3.9+  
**Purpose:** Development and testing without hardware

A pure-Python emulation of the SE applet with real ECDSA cryptography (secp256k1). Implements the same APDU interface as the Java Card applet, allowing the host SDK to be tested end-to-end.

## Payment Flow

```
    Alice (Sender)                              Bob (Receiver)
    ┌──────────┐                                ┌──────────┐
    │ Host App │                                │ Host App │
    └────┬─────┘                                └────┬─────┘
         │                                           │
         │  ①  GET_PUBLIC_KEY ──────── NFC ────────► │
         │  ◄─────────── bob_pubkey (33B) ─────────  │
         │                                           │
         │  ②  INITIATE_PAYMENT(bob_pk, 25€, ts)     │
         │     ┌────────────┐                        │
         │     │ Alice's SE │                        │
         │     │  -25€      │                        │
         │     │  cnt++     │                        │
         │     │  sign()    │                        │
         │     └────────────┘                        │
         │  ◄── signed_receipt ──────────────────────│
         │                                           │
         │  ③  receipt + alice_pubkey ── NFC ──────► │
         │                                           │
         │                          ④  RECEIVE_PAYMENT
         │                             ┌────────────┐
         │                             │  Bob's SE  │
         │                             │  verify()  │
         │                             │  +25€      │
         │                             │  cnt++     │
         │                             └────────────┘
         │                                           │
         │  ⑤  Both store receipt locally            │
         │                                           │
    ┌────┴─────┐                                ┌────┴─────┐
    │   Done   │                                │   Done   │
    └──────────┘                                └──────────┘
```

## Security Model

| Threat | Mitigation |
|---|---|
| Private key extraction | Key generated and stored inside SE; never exported |
| Balance tampering | Balance stored in SE persistent memory; atomic updates |
| Double spending | Monotonic counter; receipts synced to ledger when online |
| Replay attack | Counter + timestamp in signed receipt |
| Man-in-the-middle | ECDSA signature covers all receipt fields |
| PIN brute force | 3-attempt lockout |
| Power-loss corruption | Java Card transaction API (atomic commit/rollback) |

## Cryptographic Primitives

| Primitive | Algorithm | Standard |
|---|---|---|
| Key pair | ECDSA secp256k1 | SEC 2 |
| Signing | ECDSA SHA-256 | FIPS 186-4 |
| Hashing | SHA-256 | FIPS 180-4 |
| Key format | Compressed (33B) / Uncompressed (65B) | SEC 1 |
| Signature | DER-encoded | X.690 |

## Online Synchronization

When a device regains connectivity:

1. The **SyncManager** collects all un-synced receipts from local storage
2. Each receipt is submitted to the AEGIS Settlement API
3. The ledger validates the receipt (signature, counter, no double-spend)
4. Successfully settled receipts are marked as synced
5. Conflicts (e.g., double-spend attempts) are flagged for resolution
