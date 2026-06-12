import sys
from pathlib import Path

ETH_CLIENT_DIR = (
    Path(__file__).resolve().parents[1]
    / "aws_kms_lambda_ethereum"
    / "_lambda"
    / "functions"
    / "eth_client"
)

if str(ETH_CLIENT_DIR) not in sys.path:
    sys.path.insert(0, str(ETH_CLIENT_DIR))
