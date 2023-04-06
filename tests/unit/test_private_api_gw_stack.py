import aws_cdk as core
import aws_cdk.assertions as assertions

from private_api_gw.private_api_gw_stack import PrivateApiGwStack

# example tests. To run these tests, uncomment this file along with the example
# resource in private_api_gw/private_api_gw_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = PrivateApiGwStack(app, "private-api-gw")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
