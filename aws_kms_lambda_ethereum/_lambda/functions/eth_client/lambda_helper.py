#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import logging
import os
import sys

import asn1tools
import boto3
from eth_account import Account
from eth_account._utils.signing import (
    encode_transaction, serializable_unsigned_transaction_from_dict)
from web3.auto import w3

from eth_account.datastructures import SignedTransaction
from eth_utils import to_bytes

from crypt_function import get_cert_key, TTK_decrypt

session = boto3.session.Session()

handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(lineno)d - %(message)s')
handler.setFormatter(formatter)

_logger = logging.getLogger('app')
_logger.setLevel(os.getenv('LOGGING_LEVEL', 'WARNING'))
_logger.addHandler(handler)

# max value on curve / https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2.md
SECP256_K1_N = int("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)


class EthKmsParams:

    def __init__(self, kms_key_id: str, eth_network: str):
        self._kms_key_id = kms_key_id
        self._eth_network = eth_network

    def get_kms_key_id(self) -> str:
        return self._kms_key_id


def get_params() -> EthKmsParams:
    for param in ['KMS_KEY_ID', 'ETH_NETWORK']:
        value = os.getenv(param)

        if not value:
            if param in ['ETH_NETWORK']:
                continue
            else:
                raise ValueError('missing value for parameter: {}'.format(param))

    return EthKmsParams(
        kms_key_id=os.getenv('KMS_KEY_ID'),
        eth_network=os.getenv('ETH_NETWORK')
    )


def get_kms_public_key(key_id: str) -> bytes:
    client = boto3.client('kms')

    response = client.get_public_key(
        KeyId=key_id
    )

    return response['PublicKey']


def sign_kms(key_id: str, msg_hash: bytes) -> dict:
    client = boto3.client('kms')

    response = client.sign(
        KeyId=key_id,
        Message=msg_hash,
        MessageType='DIGEST',
        SigningAlgorithm='ECDSA_SHA_256'
    )

    return response


def calc_eth_address(pub_key: bytes) -> str:
    SUBJECT_ASN = '''
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
    '''

    key = asn1tools.compile_string(SUBJECT_ASN)
    key_decoded = key.decode('SubjectPublicKeyInfo', pub_key)

    pub_key_raw = key_decoded['subjectPublicKey'][0]
    pub_key = pub_key_raw[1:len(pub_key_raw)]

    # https://www.oreilly.com/library/view/mastering-ethereum/9781491971932/ch04.html
    hex_address = w3.keccak(bytes(pub_key)).hex()
    eth_address = '0x{}'.format(hex_address[-40:])

    eth_checksum_addr = w3.toChecksumAddress(eth_address)

    return eth_checksum_addr


def find_eth_signature(params: EthKmsParams, plaintext: bytes) -> dict:
    SIGNATURE_ASN = '''
    Signature DEFINITIONS ::= BEGIN

    Ecdsa-Sig-Value  ::=  SEQUENCE  {
           r     INTEGER,
           s     INTEGER  }

    END
    '''
    signature_schema = asn1tools.compile_string(SIGNATURE_ASN)

    signature = sign_kms(params.get_kms_key_id(), plaintext)

    # https://tools.ietf.org/html/rfc3279#section-2.2.3
    signature_decoded = signature_schema.decode('Ecdsa-Sig-Value', signature['Signature'])
    s = signature_decoded['s']
    r = signature_decoded['r']

    secp256_k1_n_half = SECP256_K1_N / 2

    if s > secp256_k1_n_half:
        s = SECP256_K1_N - s

    return {'r': r, 's': s}


def get_recovery_id(msg_hash: bytes, r: int, s: int, eth_checksum_addr: str) -> dict:
    for v in [27, 28]:
        recovered_addr = Account.recoverHash(message_hash=msg_hash,
                                             vrs=(v, r, s))

        if recovered_addr == eth_checksum_addr:
            return {'recovered_addr': recovered_addr, 'v': v}

    return {}


def get_tx_params(event: dict) -> dict:
    if 'gas' not in event or 'gasPrice' not in event or 'to' not in event or 'data' not in event:
        return {'operation': 'sign',
                'error': 'missing parameter - sign requires gas, gasPrice, to, and data to be specified'}
        
    transaction = {
        'gas': event.get('gas'),
        # 'from': event.get('from'),
        'chainId': 56,  # ChainID for Binance Smart Chain Mainnet
        'value': event.get('value'),  # Value is 0 for data transactions
        'gasPrice': event.get('gasPrice'),
        'nonce': event.get('nonce'),
        'to': event.get('to'),
        'data': event.get('data'),
        'privateKey': event.get('privateKey')
    }

    return transaction


def assemble_tx(tx_params: dict, params: EthKmsParams, eth_checksum_addr: str) -> str:
    # Desencriptamos la clave privada:
    cert_key = get_cert_key()
    private_key = TTK_decrypt(cert_key, tx_params['privateKey'])
    # Creamos la transacción firmada a partir de la transacción codificada
    # Eliminamos la variable private_key del diccionario tx_params
    del tx_params['privateKey']
    signed_tx = w3.eth.account.sign_transaction(tx_params, private_key)
    # Devolvemos la representación de cadena de la transacción firmada
    signed_tx_data = {
        'rawTransaction': signed_tx.rawTransaction.hex(),
        'hash': signed_tx.hash.hex(),
        'r': signed_tx.r,
        's': signed_tx.s,
        'v': signed_tx.v
    }
    # Devolvemos el diccionario como respuesta en formato JSON
    return signed_tx_data