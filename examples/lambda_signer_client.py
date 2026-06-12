"""
Minimal backend client: invokes the signer Lambda with transaction fields only.

No private keys are read, stored, or transmitted. The signing key never leaves
AWS KMS; Lambda only receives the unsigned transaction payload.
"""

import json
import os

import boto3
from dotenv import load_dotenv

load_dotenv()


class LambdaSigner:
    def __init__(self):
        self.lambda_client = boto3.client(
            "lambda", region_name=os.getenv("AWS_REGION", "eu-west-1")
        )
        self.function_name = os.environ["AWS_LAMBDA_FUNCTION_NAME"]

    def sign_transaction(self, transaction: dict) -> dict:
        forbidden = {"privateKey", "private_key", "mnemonic", "seed", "secret", "SKEYS"}
        if forbidden.intersection(transaction.keys()):
            raise ValueError(
                "Refusing to send secret key material to Lambda: {}".format(
                    sorted(forbidden.intersection(transaction.keys()))
                )
            )

        response = self.lambda_client.invoke(
            FunctionName=self.function_name,
            InvocationType="RequestResponse",
            Payload=json.dumps(transaction),
        )

        payload = json.load(response["Payload"])
        if "error" in payload:
            raise RuntimeError(payload["error"])

        return payload["signed_tx"]


if __name__ == "__main__":
    signer = LambdaSigner()

    # BSC Chapel testnet example — fund the KMS-derived address from a faucet first.
    unsigned_tx = {
        "to": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0",
        "nonce": 0,
        "gas": 21000,
        "gasPrice": 10_000_000_000,
        "value": 0,
        "data": "0x",
    }

    signed = signer.sign_transaction(unsigned_tx)
    print("signed tx hash:", signed["hash"])
    print("raw tx:", signed["rawTransaction"])
