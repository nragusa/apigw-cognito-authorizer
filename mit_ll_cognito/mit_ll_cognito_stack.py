from aws_cdk import (
    CfnOutput,
    RemovalPolicy,
    Stack,
    aws_apigateway as apigw,
    aws_apigatewayv2_alpha as apigateway,
    aws_apigatewayv2_authorizers_alpha as apigateway_authorizers,
    aws_apigatewayv2_integrations_alpha as apigateway_integrations,
    aws_cognito as cognito,
    aws_lambda as lambda_
)
from constructs import Construct


class MitLlCognitoStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        user_pool = cognito.UserPool(
            self,
            'TestUserPool',
            user_pool_name='MyAPIGWUserPool',
            removal_policy=RemovalPolicy.DESTROY,
            self_sign_up_enabled=True,
            sign_in_aliases=cognito.SignInAliases(email=True),
            auto_verify=cognito.AutoVerifiedAttrs(email=True),
            password_policy=cognito.PasswordPolicy(
                min_length=10,
                require_digits=True,
                require_lowercase=True,
                require_symbols=True,
                require_uppercase=True
            ),
            account_recovery=cognito.AccountRecovery.EMAIL_ONLY
        )

        user_pool_client = cognito.UserPoolClient(
            self,
            'TestUserPoolClient',
            user_pool=user_pool,
            auth_flows=cognito.AuthFlow(
                admin_user_password=True,
                user_password=True,
                custom=True,
                user_srp=True
            ),
            supported_identity_providers=[
                cognito.UserPoolClientIdentityProvider.COGNITO
            ]
        )

        hello_world_function = lambda_.Function(
            self,
            'TestLambdaFunction',
            # code=lambda_.Code.from_asset(
            #     path='functions/'
            # ),
            code=lambda_.Code.from_inline(
                '''
import json
def handler(event, context):
    return {
        'statusCode': 200,
        'body': json.dumps({'message': 'Hello World'})
    }
                '''
            ),
            runtime=lambda_.Runtime.PYTHON_3_9,
            architecture=lambda_.Architecture.X86_64,
            description='Simple function to return Hello World message behind Cognito User Pool',
            handler='index.handler'
        )

        # HTTP API stuff
        # http_api = apigateway.HttpApi(
        #     self,
        #     'TestAPIGatewayHTTPAPI',
        #     api_name='cognito-userpool-test',
        # )
        # authorizer = apigateway_authorizers.HttpUserPoolAuthorizer(
        #     'HttpAPIAuthorizer',
        #     pool=user_pool,
        #     user_pool_clients=[user_pool_client]
        # )
        # http_api.add_routes(
        #     path='/hello',
        #     authorizer=authorizer,
        #     integration=apigateway_integrations.HttpLambdaIntegration(
        #         'LambdaIntegration',
        #         handler=hello_world_function,
        #     )
        # )

        # REST API stuff
        rest_api = apigw.RestApi(
            self,
            'TestRESTAPI',
            description='REST API that uses Cognito user pool for authorization',
            endpoint_configuration=apigw.EndpointConfiguration(
                types=[apigw.EndpointType.REGIONAL]
            ),
            deploy_options=apigw.StageOptions(
                description='Default stage for this API',
                data_trace_enabled=True,
                metrics_enabled=True
            ),
            deploy=True,
            cloud_watch_role=True
        )
        rest_authorizer = apigw.CognitoUserPoolsAuthorizer(
            self,
            'RESTAuthorizer',
            cognito_user_pools=[user_pool]
        )
        hello = rest_api.root.add_resource('hello')
        hello.add_method(
            'GET',
            integration=apigw.LambdaIntegration(
                handler=hello_world_function,
                proxy=True
            ),
            authorizer=rest_authorizer,
            authorization_type=apigw.AuthorizationType.COGNITO
        )

        CfnOutput(
            self,
            'UserPoolClient',
            description='The user pool application client ID',
            value=user_pool_client.user_pool_client_id
        )
        CfnOutput(
            self,
            'UserPool',
            description='The user pool ID',
            value=user_pool.user_pool_id
        )
