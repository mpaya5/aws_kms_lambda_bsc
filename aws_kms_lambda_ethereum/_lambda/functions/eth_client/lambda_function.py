#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import logging
import os

from lambda_helper import (assemble_tx,
                           get_params,
                           get_tx_params,
                           calc_eth_address,
                           get_kms_public_key)

LOG_LEVEL = os.getenv("LOG_LEVEL", "WARNING")
LOG_FORMAT = "%(levelname)s:%(lineno)s:%(message)s"
handler = logging.StreamHandler()

_logger = logging.getLogger()
_logger.setLevel(LOG_LEVEL)


def lambda_handler(event, context):
    _logger.debug("incoming event: {}".format(event))

    try:
        params = get_params()
    except Exception as e:
        raise e

    # get key_id from environment varaible
    key_id = os.getenv('KMS_KEY_ID')

    # download public key from KMS
    pub_key = get_kms_public_key(key_id)

    # calculate the Ethereum public address from public key
    eth_checksum_addr = calc_eth_address(pub_key)

    # collect raw parameters for Ethereum transaction
    tx_params = get_tx_params(event)

    # assemble Ethereum transaction and sign it offline
    raw_tx_signed = assemble_tx(tx_params=tx_params,
                                params=params,
                                eth_checksum_addr=eth_checksum_addr)

    return {"signed_tx": raw_tx_signed}
