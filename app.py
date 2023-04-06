#!/usr/bin/env python3
import os

import aws_cdk as cdk

from private_api_gw.private_api_gw_stack import PrivateApiGwStack


app = cdk.App()
PrivateApiGwStack(
    app,
    'PrivateApiGwStack',
    description='Creates a demo of API Gateway with private integration backed by an EC2 instance',
    tags={
        'Project': 'API Gateway Demo'
    }
)

app.synth()
