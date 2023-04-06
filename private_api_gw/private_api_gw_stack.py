from aws_cdk import (
    CfnOutput,
    Duration,
    RemovalPolicy,
    Stack,
    aws_apigateway as apigw,
    # aws_apigatewayv2_alpha as apigateway,
    # aws_apigatewayv2_authorizers_alpha as apigateway_authorizers,
    # aws_apigatewayv2_integrations_alpha as apigateway_integrations,
    aws_cognito as cognito,
    aws_ec2 as ec2,
    aws_elasticloadbalancingv2 as elbv2,
    aws_elasticloadbalancingv2_targets as elbv2_targets,
    aws_iam as iam
    # aws_lambda as lambda_
)
from constructs import Construct


class PrivateApiGwStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        vpc = ec2.Vpc(
            self,
            'VpcForPrivateEndpoint',
            ip_addresses=ec2.IpAddresses.cidr('10.10.0.0/16'),
            max_azs=2,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name='public',
                    subnet_type=ec2.SubnetType.PUBLIC
                ),
                ec2.SubnetConfiguration(
                    name='private',
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
                )
            ],
            nat_gateways=1
        )

        # VPC Endpoint definitions
        vpc_endpoint_sg = ec2.SecurityGroup(
            self,
            'VpcEndpointSecurityGroup',
            vpc=vpc,
            description='Allow connections to this endpoint',
            security_group_name='api-gateway-endpoint'
        )
        vpc_endpoint_sg.add_ingress_rule(
            peer=ec2.Peer.ipv4(vpc.vpc_cidr_block),
            connection=ec2.Port.tcp(443),
            description='Allow connectivity from within the VPC'
        )
        vpc_endpoint = ec2.InterfaceVpcEndpoint(
            self,
            'ApiGatewayVpcEndpoint',
            vpc=vpc,
            service=ec2.InterfaceVpcEndpointAwsService.APIGATEWAY,
            private_dns_enabled=True,
            security_groups=[vpc_endpoint_sg]
        )

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
                types=[apigw.EndpointType.PRIVATE],
                vpc_endpoints=[vpc_endpoint]
            ),
            deploy_options=apigw.StageOptions(
                description='Default stage for this API',
                data_trace_enabled=True,
                metrics_enabled=True
            ),
            deploy=True,
            cloud_watch_role=True,
            policy=iam.PolicyDocument(
                statements=[
                    iam.PolicyStatement(
                        actions=['execute-api:Invoke'],
                        effect=iam.Effect.ALLOW,
                        principals=[iam.AnyPrincipal()],
                        resources=['execute-api:/*'],
                    ),
                    iam.PolicyStatement(
                        actions=['execute-api:Invoke'],
                        effect=iam.Effect.DENY,
                        resources=['execute-api:/*'],
                        principals=[iam.AnyPrincipal()],
                        conditions={
                            'StringNotEquals': {
                                'aws:SourceVpce': vpc_endpoint.vpc_endpoint_id
                            }
                        }
                    )
                ]
            )
        )
        rest_authorizer = apigw.CognitoUserPoolsAuthorizer(
            self,
            'RESTAuthorizer',
            cognito_user_pools=[user_pool]
        )

        hello = rest_api.root.add_resource('hello')
        # hello.add_method(
        #     'GET',
        #     integration=apigw.LambdaIntegration(
        #         handler=hello_world_function,
        #         proxy=True
        #     ),
        #     authorizer=rest_authorizer,
        #     authorization_type=apigw.AuthorizationType.COGNITO
        # )

        # EC2 instance user data to install / start Apache after initial launch
        user_data = ec2.UserData.for_linux()
        user_data.add_commands(
            'yum -y install httpd',
            'echo "Hello World!" > /var/www/html/index.html',
            'systemctl start httpd'
        )
        # EC2 instance security group
        my_ec2_sg = ec2.SecurityGroup(
            self,
            'Ec2ApiInstanceSecurityGroup',
            description='Security group for the EC2 API instance',
            vpc=vpc
        )
        my_ec2_sg.add_ingress_rule(
            peer=ec2.Peer.ipv4(vpc.vpc_cidr_block),
            connection=ec2.Port.tcp(80),
            description='Allow HTTP connectivity to the instance from within the VPC'
        )
        # EC2 instance
        my_ec2 = ec2.Instance(
            self,
            'Ec2ApiInstance',
            instance_type=ec2.InstanceType('t3.large'),
            machine_image=ec2.MachineImage.latest_amazon_linux(
                generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2
            ),
            vpc=vpc,
            user_data=user_data,
            security_group=my_ec2_sg
        )
        my_ec2.role.add_managed_policy(
            policy=iam.ManagedPolicy.from_aws_managed_policy_name(
                'AmazonSSMManagedEC2InstanceDefaultPolicy'
            )
        )

        # Create the NLB
        nlb = elbv2.NetworkLoadBalancer(
            self,
            'NetworkLoadBalancer',
            vpc=vpc,
            internet_facing=False,
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
            )
        )
        # Create a target group, targeting the EC2 instance
        ec2_target_group = elbv2.NetworkTargetGroup(
            self,
            'NetworkLoadBalancerTargetGroup',
            port=80,
            protocol=elbv2.Protocol.TCP,
            health_check=elbv2.HealthCheck(
                protocol=elbv2.Protocol.HTTP,
                healthy_threshold_count=2,
                path='/',
                unhealthy_threshold_count=2,
                interval=Duration.seconds(10),
                healthy_http_codes='200'
            ),
            targets=[
                elbv2_targets.InstanceIdTarget(
                    instance_id=my_ec2.instance_id,
                    port=80
                )
            ],
            vpc=vpc
        )
        # Create a listener on the NLB
        elbv2.NetworkListener(
            self,
            'NetworkLoadBalancerListener',
            load_balancer=nlb,
            port=80,
            default_target_groups=[ec2_target_group]
        )

        # VPC link for API Gateway -> NLB integration
        vpc_link = apigw.VpcLink(
            self,
            'ApiGatewayVpcLink',
            description='VPC Link for API Gateway',
            targets=[nlb]
        )
        hello.add_method(
            http_method='GET',
            integration=apigw.Integration(
                type=apigw.IntegrationType.HTTP_PROXY,
                integration_http_method='GET',
                options=apigw.IntegrationOptions(
                    connection_type=apigw.ConnectionType.VPC_LINK,
                    vpc_link=vpc_link
                )
            ),
            authorizer=rest_authorizer,
            authorization_type=apigw.AuthorizationType.COGNITO
        )

        # CloudFormation outputs
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
        CfnOutput(
            self,
            'LoadBalancerUrl',
            description='The URL of the network load balancer',
            value=f'https://{nlb.load_balancer_dns_name}/'
        )
