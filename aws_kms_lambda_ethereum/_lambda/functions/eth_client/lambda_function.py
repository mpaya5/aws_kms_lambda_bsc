#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import logging
import os

from lambda_helper import (
    assemble_tx,
    calc_eth_address,
    get_kms_public_key,
    get_params,
    get_tx_params,
)

LOG_LEVEL = os.getenv("LOG_LEVEL", "WARNING")
LOG_FORMAT = "%(levelname)s:%(lineno)s:%(message)s"
handler = logging.StreamHandler()

_logger = logging.getLogger()
_logger.setLevel(LOG_LEVEL)


def lambda_handler(event, context):
    _logger.debug("incoming event keys: %s", sorted(event.keys()))

    params = get_params()
    key_id = params.get_kms_key_id()
    pub_key = get_kms_public_key(key_id)
    eth_checksum_addr = calc_eth_address(pub_key)

    tx_params = get_tx_params(event, chain_id=params.get_chain_id())

    try:
        raw_tx_signed = assemble_tx(
            tx_params=tx_params,
            params=params,
            eth_checksum_addr=eth_checksum_addr,
        )
    except ValueError as exc:
        return {"error": str(exc)}

    return {"signed_tx": raw_tx_signed}
