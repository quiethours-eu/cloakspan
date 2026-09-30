"""Shared test values, independent of pytest fixture discovery."""

VAULT_KEY = b"\x01" * 32
TOKEN_KEY = b"\x02" * 32
OTHER_TOKEN_KEY = b"\x03" * 32
VAULT_KEY_V2 = b"\x04" * 32

TEST_API_KEY = "sgw_live_test_key_for_tenant_a"
TEST_API_KEY_B = "sgw_live_test_key_for_tenant_b"


def _lv_with_valid_checksum(first_ten: str) -> str:
    weights = (1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
    total = sum(int(first_ten[i]) * weights[i] for i in range(10))
    check = (1101 - total) % 11 % 10
    return f"{first_ten[:6]}-{first_ten[6:]}{check}"


def _baltic_with_valid_checksum(first_ten: str) -> str:
    w1 = (1, 2, 3, 4, 5, 6, 7, 8, 9, 1)
    w2 = (3, 4, 5, 6, 7, 8, 9, 1, 2, 3)
    remainder = sum(int(first_ten[i]) * w1[i] for i in range(10)) % 11
    if remainder == 10:
        remainder = sum(int(first_ten[i]) * w2[i] for i in range(10)) % 11
        if remainder == 10:
            remainder = 0
    return first_ten + str(remainder)


# Generated from the published check-digit algorithms and reused by both suites.
VALID_LV_CODE = _lv_with_valid_checksum("1203851234")
VALID_LT_CODE = _baltic_with_valid_checksum("3850312123")
VALID_EE_CODE = _baltic_with_valid_checksum("3850312123")
