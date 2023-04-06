from aws_cdk import (
    CfnOutput,
    Duration,
    RemovalPolicy,
    Stack,
    aws_apigateway as apigw,
    aws_cognito as cognito,
    aws_ec2 as ec2,
    aws_elasticloadbalancingv2 as elbv2,
    aws_elasticloadbalancingv2_targets as elbv2_targets,
    aws_iam as iam
)
from constructs import Construct


class PrivateApiGwStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Creates a VPC with CIDR 10.10.0.0/16
        # 2 public subnets with 1 NAT gateway
        # 2 private subnets
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

        # Create a VPC endpoint for API Gateway. This will create 2 ENIs
        # (elastic network interfaces) in the private subnets of the VPC
        # created above. When a client wants to make a request to the
        # API Gateway, it will send the request to one of these endpoints.
        # A security group is required for these ENIs and is configured
        # to allow access to port 443 over TCP
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

        # A basic Cognito user pool to store username / passwords
        # and provide authorization to the API Gateway endpoint
        # Clients must authenticate and get an ID token before calling
        # the API Gateway endpoint
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

        # Creates the API Gateway REST endpoint. It is configured to be
        # private and to be accessed through the VPC endpoint created earlier.
        # There is also a policy associated to this that dictates access
        # to this endpoint can only be granted through the VPC endpoint.
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

        # EC2 instance user data which will install Apache, create
        # an index.html file to be served from the root directory,
        # and enable Apache to start on boot. This only gets executed
        # once after the initial creation of the instance.
        user_data = ec2.UserData.for_linux()
        user_data.add_commands(
            'yum -y install httpd',
            'echo "Hello World!" > /var/www/html/index.html',
            'systemctl enable httpd',
            'systemctl start httpd'
        )
        # The security group for this instance which will allow access
        # to port 80 from the VPC CIDR range
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
        # Creates a t3.large EC2 instance using the latest Amazon Linux 2
        # AMI. Also uses the security group and user data defined above.
        # Adds a policy to allow this instance to be managed by
        # AWS Systems Manager.
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

        # Create a Network Load Balancer for use with VPC link. This
        # allows API Gateway private integration with the EC2 instance
        # created above.
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

        # Create the 'hello' resource and method onto the REST API
        # that uses VPC link for the integration and Cognito for authorization
        hello = rest_api.root.add_resource('hello')
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
