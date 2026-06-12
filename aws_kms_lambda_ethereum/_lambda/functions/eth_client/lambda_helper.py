#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import logging
import os
import sys

import asn1tools
import boto3
from eth_account import Account
from eth_account._utils.signing import (
    encode_transaction,
    serializable_unsigned_transaction_from_dict,
)
from signing_core import (
    compute_eip155_v,
    get_tx_params,
    normalize_signature_s,
    resolve_chain_id,
)
from web3.auto import w3

session = boto3.session.Session()

handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(lineno)d - %(message)s"
)
handler.setFormatter(formatter)

_logger = logging.getLogger("app")
_logger.setLevel(os.getenv("LOGGING_LEVEL", "WARNING"))
_logger.addHandler(handler)


class EthKmsParams:

    def __init__(self, kms_key_id: str, eth_network: str, chain_id: int):
        self._kms_key_id = kms_key_id
        self._eth_network = eth_network
        self._chain_id = chain_id

    def get_kms_key_id(self) -> str:
        return self._kms_key_id

    def get_eth_network(self) -> str:
        return self._eth_network

    def get_chain_id(self) -> int:
        return self._chain_id


def get_params() -> EthKmsParams:
    kms_key_id = os.getenv("KMS_KEY_ID")
    if not kms_key_id:
        raise ValueError("missing value for parameter: KMS_KEY_ID")

    eth_network = os.getenv("ETH_NETWORK", "bsc")
    chain_id = resolve_chain_id(eth_network)

    return EthKmsParams(
        kms_key_id=kms_key_id,
        eth_network=eth_network,
        chain_id=chain_id,
    )


def get_kms_public_key(key_id: str) -> bytes:
    client = boto3.client("kms")

    response = client.get_public_key(KeyId=key_id)

    return response["PublicKey"]


def sign_kms(key_id: str, msg_hash: bytes) -> dict:
    client = boto3.client("kms")

    response = client.sign(
        KeyId=key_id,
        Message=msg_hash,
        MessageType="DIGEST",
        SigningAlgorithm="ECDSA_SHA_256",
    )

    return response


def calc_eth_address(pub_key: bytes) -> str:
    SUBJECT_ASN = """
    Key DEFINITIONS ::= BEGIN

    SubjectPublicKeyInfo  ::=  SEQUENCE  {
       algorithm         AlgorithmIdentifier,
       subjectPublicKey  BIT STRING
     }

    AlgorithmIdentifier  ::=  SEQUENCE  {
        algorithm   OBJECT IDENTIFIER,
        parameters  ANY DEFINED BY algorithm OPTIONAL
      }

    END
    """

    key = asn1tools.compile_string(SUBJECT_ASN)
    key_decoded = key.decode("SubjectPublicKeyInfo", pub_key)

    pub_key_raw = key_decoded["subjectPublicKey"][0]
    pub_key = pub_key_raw[1 : len(pub_key_raw)]

    # https://www.oreilly.com/library/view/mastering-ethereum/9781491971932/ch04.html
    hex_address = w3.keccak(bytes(pub_key)).hex()
    eth_address = "0x{}".format(hex_address[-40:])

    eth_checksum_addr = w3.toChecksumAddress(eth_address)

    return eth_checksum_addr


def find_eth_signature(params: EthKmsParams, plaintext: bytes) -> dict:
    SIGNATURE_ASN = """
    Signature DEFINITIONS ::= BEGIN

    Ecdsa-Sig-Value  ::=  SEQUENCE  {
           r     INTEGER,
           s     INTEGER  }

    END
    """
    signature_schema = asn1tools.compile_string(SIGNATURE_ASN)

    signature = sign_kms(params.get_kms_key_id(), plaintext)

    # https://tools.ietf.org/html/rfc3279#section-2.2.3
    signature_decoded = signature_schema.decode(
        "Ecdsa-Sig-Value", signature["Signature"]
    )
    r = signature_decoded["r"]
    s = normalize_signature_s(signature_decoded["s"])

    return {"r": r, "s": s}


def get_recovery_id(msg_hash: bytes, r: int, s: int, eth_checksum_addr: str) -> dict:
    for v in [27, 28]:
        recovered_addr = Account.recoverHash(message_hash=msg_hash, vrs=(v, r, s))

        if recovered_addr == eth_checksum_addr:
            return {"recovered_addr": recovered_addr, "v": v}

    return {}


def assemble_tx(
    tx_params: dict, params: EthKmsParams, eth_checksum_addr: str
) -> dict:
    if "error" in tx_params:
        raise ValueError(tx_params["error"])

    tx_unsigned = serializable_unsigned_transaction_from_dict(tx_params)
    tx_hash = tx_unsigned.hash()

    tx_sig = find_eth_signature(params=params, plaintext=tx_hash)
    tx_eth_recovered = get_recovery_id(
        tx_hash, tx_sig["r"], tx_sig["s"], eth_checksum_addr
    )

    if not tx_eth_recovered:
        raise ValueError(
            "could not recover signing address from KMS signature; "
            "verify KMS_KEY_ID matches the intended BSC account"
        )

    v = compute_eip155_v(tx_eth_recovered["v"], tx_params["chainId"])
    tx_encoded = encode_transaction(
        tx_unsigned, vrs=(v, tx_sig["r"], tx_sig["s"])
    )

    return {
        "rawTransaction": tx_encoded.hex(),
        "hash": w3.keccak(tx_encoded).hex(),
        "r": tx_sig["r"],
        "s": tx_sig["s"],
        "v": v,
        "from": eth_checksum_addr,
        "chainId": tx_params["chainId"],
    }
