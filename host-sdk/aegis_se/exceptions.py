"""
AEGIS Offline Payments — Custom Exceptions
"""


class AegisError(Exception):
    """Base exception for all AEGIS SE errors."""

    pass


class APDUError(AegisError):
    """Raised when the SE returns a non-success status word."""

    SW_MESSAGES = {
        0x6985: "Insufficient funds or conditions not satisfied",
        0x6A80: "Invalid amount",
        0x6982: "PIN verification required",
        0x63C0: "PIN incorrect (0 retries left)",
        0x63C1: "PIN incorrect (1 retry left)",
        0x63C2: "PIN incorrect (2 retries left)",
        0x63C3: "PIN incorrect (3 retries left)",
        0x6A84: "Counter overflow",
        0x6988: "Signature verification failed",
        0x6700: "Wrong data length",
        0x6E00: "CLA not supported",
        0x6D00: "INS not supported",
    }

    def __init__(self, sw1: int, sw2: int):
        self.sw1 = sw1
        self.sw2 = sw2
        self.sw = (sw1 << 8) | sw2
        msg = self.SW_MESSAGES.get(self.sw, f"Unknown error")
        super().__init__(f"APDU Error SW=0x{self.sw:04X}: {msg}")


class InsufficientFundsError(APDUError):
    """Raised when the wallet has insufficient balance."""

    pass


class InvalidAmountError(APDUError):
    """Raised when the payment amount is invalid."""

    pass


class PINError(APDUError):
    """Raised when PIN verification fails."""

    @property
    def retries_remaining(self) -> int:
        return self.sw & 0x0F


class SignatureError(APDUError):
    """Raised when a cryptographic signature is invalid."""

    pass


class CommunicationError(AegisError):
    """Raised when NFC / SE communication fails."""

    pass


class KeysNotInitializedError(AegisError):
    """Raised when attempting crypto without key generation."""

    pass


class SyncError(AegisError):
    """Raised when online synchronization fails."""

    pass
