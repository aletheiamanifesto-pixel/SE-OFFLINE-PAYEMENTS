# AEGIS Offline Payments — APDU Protocol Specification

## Overview

Communication between the host application and the AEGIS Secure Element applet uses **ISO 7816-4 APDU** (Application Protocol Data Unit) commands transmitted over NFC (ISO 14443) or contact interface.

## APDU Format

### Command APDU

```
┌─────┬─────┬────┬────┬────┬──────────┬────┐
│ CLA │ INS │ P1 │ P2 │ Lc │   Data   │ Le │
│ 1B  │ 1B  │ 1B │ 1B │ 1B │ 0-255B   │ 1B │
└─────┴─────┴────┴────┴────┴──────────┴────┘
```

- **CLA** = `0x80` (proprietary class for AEGIS)
- **INS** = Instruction code (see table below)
- **P1, P2** = Parameters (usually `0x00`)
- **Lc** = Length of data field
- **Data** = Command payload
- **Le** = Expected response length

### Response APDU

```
┌──────────┬─────┬─────┐
│   Data   │ SW1 │ SW2 │
│ 0-256B   │ 1B  │ 1B  │
└──────────┴─────┴─────┘
```

## Application Identifier (AID)

```
AID: A0 00 00 08 47  41 45 47 49 53 01
     ├─ RID (5B) ─┤  ├── PIX (6B) ──┤
```

Select the applet with a standard SELECT command before issuing AEGIS commands.

## Command Reference

### GET_VERSION (0x02)

Query the applet version.

| Field | Value |
|-------|-------|
| CLA | `0x80` |
| INS | `0x02` |
| P1, P2 | `0x00`, `0x00` |
| Lc | — |
| Le | `0x03` |

**Response:** 3 bytes `[major, minor, patch]`

---

### GET_BALANCE (0x10)

Query the current wallet balance.

| Field | Value |
|-------|-------|
| CLA | `0x80` |
| INS | `0x10` |
| P1, P2 | `0x00`, `0x00` |
| Lc | — |
| Le | `0x04` |

**Response:** 4 bytes (big-endian `uint32`, euro-cents)

**Example:** `0x000009C4` = 2500 = **25.00 €**

---

### GET_COUNTER (0x12)

Query the monotonic transaction counter.

| Field | Value |
|-------|-------|
| CLA | `0x80` |
| INS | `0x12` |
| P1, P2 | `0x00`, `0x00` |
| Lc | — |
| Le | `0x04` |

**Response:** 4 bytes (big-endian `uint32`)

---

### GET_PUBLIC_KEY (0x14)

Export the wallet's compressed public key.

| Field | Value |
|-------|-------|
| CLA | `0x80` |
| INS | `0x14` |
| P1, P2 | `0x00`, `0x00` |
| Lc | — |
| Le | `0x21` (33) |

**Response:** 33 bytes (compressed secp256k1 public key: `02`/`03` prefix + 32-byte X)

---

### INITIATE_PAYMENT (0x20)

Debit the wallet and produce a signed payment receipt.

| Field | Value |
|-------|-------|
| CLA | `0x80` |
| INS | `0x20` |
| P1, P2 | `0x00`, `0x00` |
| Lc | `0x2D` (45) |
| Data | See below |
| Le | `0x00` |

**Data layout (45 bytes):**

| Offset | Length | Field |
|--------|--------|-------|
| 0 | 33 | Receiver compressed public key |
| 33 | 4 | Amount (big-endian `uint32`, euro-cents) |
| 37 | 8 | Timestamp (big-endian `uint64`, unix millis) |

**Response:** Signed receipt (83 + signature bytes, typically 83–155 bytes total)

**Errors:**
- `0x6A80` — Invalid amount (zero, negative, or > 500.00 €)
- `0x6985` — Insufficient funds

---

### RECEIVE_PAYMENT (0x22)

Verify and credit an incoming payment from a peer.

| Field | Value |
|-------|-------|
| CLA | `0x80` |
| INS | `0x22` |
| P1, P2 | `0x00`, `0x00` |
| Lc | Variable (≥ 156) |
| Data | See below |

**Data layout:**

| Offset | Length | Field |
|--------|--------|-------|
| 0 | 65 | Sender uncompressed public key |
| 65 | Variable | Signed receipt from sender |

**Response:** Empty (success = SW `0x9000`)

**Errors:**
- `0x6988` — Signature verification failed
- `0x6A80` — Invalid amount
- `0x6985` — Balance would exceed maximum
- `0x6700` — Wrong data length

---

### GET_LAST_RECEIPT (0x40)

Retrieve the last stored transaction receipt.

| Field | Value |
|-------|-------|
| CLA | `0x80` |
| INS | `0x40` |
| P1, P2 | `0x00`, `0x00` |
| Lc | — |
| Le | `0x00` |

**Response:** Receipt bytes (or empty if no receipt stored)

---

### LOAD_BALANCE (0x50)

Load funds into the wallet. **Requires prior PIN verification.**

| Field | Value |
|-------|-------|
| CLA | `0x80` |
| INS | `0x50` |
| P1, P2 | `0x00`, `0x00` |
| Lc | `0x04` |
| Data | Amount (big-endian `uint32`, euro-cents) |

**Response:** Empty (success = SW `0x9000`)

**Errors:**
- `0x6982` — PIN not verified
- `0x6A80` — Invalid amount
- `0x6985` — Balance would exceed 3000.00 €

---

### VERIFY_PIN (0x60)

Verify the 6-digit PIN to unlock privileged operations.

| Field | Value |
|-------|-------|
| CLA | `0x80` |
| INS | `0x60` |
| P1, P2 | `0x00`, `0x00` |
| Lc | `0x06` |
| Data | PIN (6 bytes, ASCII digits) |

**Response:** Empty (success = SW `0x9000`)

**Errors:**
- `0x63CX` — PIN incorrect, X = retries remaining (0–3)
- `0x6700` — Wrong PIN length

---

### GENERATE_KEYS (0x70)

Generate a fresh ECDSA secp256k1 key pair. Destroys any existing keys.

| Field | Value |
|-------|-------|
| CLA | `0x80` |
| INS | `0x70` |
| P1, P2 | `0x00`, `0x00` |
| Lc | — |
| Le | `0x21` (33) |

**Response:** 33 bytes (new compressed public key)

---

## Status Words

| SW | Meaning |
|----|---------|
| `0x9000` | Success |
| `0x6700` | Wrong data length |
| `0x6982` | PIN verification required |
| `0x63CX` | PIN incorrect, X retries remaining |
| `0x6985` | Conditions not satisfied / insufficient funds |
| `0x6988` | Signature verification failed |
| `0x6A80` | Invalid data (amount out of range) |
| `0x6A84` | Counter overflow |
| `0x6D00` | Instruction not supported |
| `0x6E00` | Class not supported |

## Receipt Binary Format (v1)

```
Offset  Length  Field
──────  ──────  ─────────────────────────
0       1       Version (0x01)
1       33      Sender compressed pubkey
34      33      Receiver compressed pubkey
67      4       Amount (uint32 BE, euro-cents)
71      4       Counter (uint32 BE)
75      8       Timestamp (uint64 BE, unix millis)
83      var     ECDSA signature (DER-encoded)
```

Total size: 83 bytes header + 70–72 bytes signature ≈ **153–155 bytes**

The signature covers bytes `[0..82]` (the entire header).
