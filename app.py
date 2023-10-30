#!/usr/bin/env python3

#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import os
from aws_cdk import App

from aws_kms_lambda_ethereum.aws_kms_lambda_ethereum_stack import AwsKmsLambdaEthereumStack

app = App()
AwsKmsLambdaEthereumStack(app, "aws-kms-lambda-ethereum")

app.synth()
