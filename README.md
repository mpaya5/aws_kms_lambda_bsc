# AWS KMS Lambda for BSC Network

## Introduction

AWS provides code for AWS KMS Lambda primarily intended for Ethereum. However, at the time of this adaptation, there was no documentation or support from AWS for the Binance Smart Chain (BSC) network. This project introduces modifications to make AWS KMS Lambda compatible with BSC.

## Modifications

The following major changes were made:

- **Function Adaptations for BSC Network:**
    - Adjusted the functions `get_tx_params` and `assemble_tx` in the `aws_kms_lambda_ethereum/_lambda/functions/eth_client/lambda_helper.py` file to suit the BSC network requirements.
- **Decryption System:**
    - A private decryption system was integrated. When a key is sent to Lambda, it's encrypted. The decryption keys reside within this function, ensuring the safe handling and signature of the request.

## Output

The system returns values in the following format:
```
    signed_tx_data = {
        'rawTransaction': signed_tx.rawTransaction.hex(),
        'hash': signed_tx.hash.hex(),
        'r': signed_tx.r,
        's': signed_tx.s,
        'v': signed_tx.v
    }
```

## Utility Script

If you need a script to send a hash to Lambda, here's an example:

```
import boto3
import json
import os
import base64
from eth_account.datastructures import SignedTransaction
from dotenv import load_dotenv

load_dotenv()

class LambdaSigner:
    def __init__(self):
        self.lambda_client = boto3.client('lambda')
        self.function_name = os.getenv('AWS_LAMBDA_FUNCTION_NAME')

    def sign_transaction(self, transaction_data):
        # Add the private_key to the transaction_data object
        transaction_data['privateKey'] = os.getenv('SKEYS')
        response = self.lambda_client.invoke(
            FunctionName=self.function_name,
            InvocationType='RequestResponse',
            Payload=json.dumps(transaction_data),
        )

        response_payload = json.load(response['Payload'])
        signed_tx = SignedTransaction(
            rawTransaction=response_payload['signed_tx']['rawTransaction'],
            hash=response_payload['signed_tx']['hash'],
            r=int(response_payload['signed_tx']['r']),
            s=int(response_payload['signed_tx']['s']),
            v=response_payload['signed_tx']['v']
        )

        return signed_tx
```

This README.md provides a clear overview of the modifications and offers a utility script to interact with the adapted AWS KMS Lambda for the BSC network. Adjust as needed to fit the specifics of your project and its documentation requirements.