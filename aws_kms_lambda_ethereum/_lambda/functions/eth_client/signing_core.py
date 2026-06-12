#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import os
from typing import Optional

SECP256_K1_N = int(
    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16
)

BSC_CHAIN_IDS = {
    "bsc": 56,
    "bsc-mainnet": 56,
    "bsc-testnet": 97,
    "chapel": 97,
}

FORBIDDEN_SECRET_FIELDS = frozenset(
    {"privateKey", "private_key", "mnemonic", "seed", "secret", "SKEYS"}
)


def resolve_chain_id(eth_network: Optional[str] = None) -> int:
    explicit = os.getenv("CHAIN_ID")
    if explicit:
        return int(explicit)

    network = (eth_network or os.getenv("ETH_NETWORK") or "bsc").lower()
    if network in BSC_CHAIN_IDS:
        return BSC_CHAIN_IDS[network]

    raise ValueError(
        "unsupported ETH_NETWORK '{}'; set CHAIN_ID explicitly or use one of {}".format(
            network, ", ".join(sorted(BSC_CHAIN_IDS))
        )
    )


def normalize_signature_s(s: int) -> int:
    """Apply EIP-2 low-s normalization for Ethereum-compatible chains."""
    secp256_k1_n_half = SECP256_K1_N // 2
    if s > secp256_k1_n_half:
        return SECP256_K1_N - s
    return s


def compute_eip155_v(recovery_v: int, chain_id: int) -> int:
    """Convert legacy recovery id (27/28) to EIP-155 encoded v."""
    return recovery_v - 27 + chain_id * 2 + 35


def get_tx_params(event: dict, chain_id: int) -> dict:
    forbidden = FORBIDDEN_SECRET_FIELDS.intersection(event.keys())
    if forbidden:
        return {
            "error": "refusing request: secret key material must not be sent to the signer ({})".format(
                ", ".join(sorted(forbidden))
            )
        }

    required = ("gas", "gasPrice", "to", "nonce", "data")
    missing = [field for field in required if field not in event]
    if missing:
        return {
            "error": "missing parameter(s) - sign requires {}".format(
                ", ".join(missing)
            )
        }

    return {
        "chainId": chain_id,
        "gas": event["gas"],
        "gasPrice": event["gasPrice"],
        "nonce": event["nonce"],
        "to": event["to"],
        "data": event["data"],
        "value": event.get("value", 0),
    }
