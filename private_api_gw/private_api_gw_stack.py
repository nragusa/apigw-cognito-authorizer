from aws_cdk import (
    CfnOutput,
    Duration,
    RemovalPolicy,
    Stack,
    aws_apigateway as apigw,
    aws_cognito as cognito,
    aws_ec2 as ec2,
    aws_ecs as ecs,
    aws_ecs_patterns as ecs_patterns,
    aws_elasticloadbalancingv2 as elbv2,
    aws_elasticloadbalancingv2_targets as elbv2_targets,
    aws_iam as iam,
    aws_logs as logs,
    aws_secretsmanager as secretsmanager,
    aws_servicediscovery as servicediscovery
)
from constructs import Construct
import os


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

        # Use this instance to test the API with. You can
        # connect to this instance using AWS Systems Manager
        # Session Manager: https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html
        client_ec2_instance = ec2.Instance(
            self,
            'ClientEc2Instance',
            instance_type=ec2.InstanceType('t3.large'),
            machine_image=ec2.MachineImage.latest_amazon_linux(
                generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2
            ),
            vpc=vpc,
            instance_name='client-test'
        )
        client_ec2_instance.role.add_managed_policy(
            policy=iam.ManagedPolicy.from_aws_managed_policy_name(
                'AmazonSSMManagedEC2InstanceDefaultPolicy'
            )
        )

        ###### ECS Infrastructure ######
        # ECS cluster
        cluster = ecs.Cluster(
            self,
            'EcsCluster',
            vpc=vpc
        )

        # Namespace with AWS Cloud Map for service discovery
        # This is basically a private tld for the services
        # to discover one another via DNS.
        namespace = servicediscovery.PrivateDnsNamespace(
            self,
            'PrivateDnsNamespace',
            vpc=vpc,
            name=self.node.try_get_context('NAMESPACE'),
            description='Namespace for the threat demo services'
        )

        # Generate a password for the PostgreSQL database
        # and store it securely in secrets manager
        postgres_password = secretsmanager.Secret(
            self,
            'PostgreSQLPassword',
            description='PostgreSQL password for the threats DB',
            generate_secret_string=secretsmanager.SecretStringGenerator(
                password_length=24,
                exclude_punctuation=True,
                include_space=False
            ),
            secret_name='threat-demo/POSTGRES_PASSWORD'
        )

        # security group for Postgres
        postgres_sg = ec2.SecurityGroup(
            self,
            'PostgresSecurityGroup',
            vpc=vpc,
            description='Security group for the Postgres DB ECS Fargate service'
        )
        # security group for data api
        api_sg = ec2.SecurityGroup(
            self,
            'ApiSecurityGroup',
            vpc=vpc,
            description='Security group for the data API ECS Fargate service'
        )
        # Allow inbound access to the DB security group
        # from the API containers on port 5432
        postgres_sg.add_ingress_rule(
            peer=api_sg,
            connection=ec2.Port.tcp(5432),
            description='Allow connectivity from API containers to port 5432'
        )

        ###### Database ######
        # Postgres task definition
        postgres_task = ecs.TaskDefinition(
            self,
            'PostgresTask',
            compatibility=ecs.Compatibility.FARGATE,
            cpu='1024',
            memory_mib='2048'
        )
        # Postgres container definition
        postgres_task.add_container(
            'PostgresContainer',
            image=ecs.ContainerImage.from_registry(
                'postgres:15.2'
            ),
            environment={
                'POSTGRES_USER': self.node.try_get_context('POSTGRES_USER'),
                'POSTGRES_DB': self.node.try_get_context('POSTGRES_DB')
            },
            secrets={
                'POSTGRES_PASSWORD': ecs.Secret.from_secrets_manager(postgres_password)
            },
            logging=ecs.AwsLogDriver(
                stream_prefix='threat-demo-db',
                log_group=logs.LogGroup(
                    self,
                    'LogGroupDB',
                    retention=logs.RetentionDays.THREE_MONTHS
                )
            ),
            port_mappings=[
                ecs.PortMapping(
                    host_port=5432,
                    container_port=5432
                )
            ]
        )
        ecs.FargateService(
            self,
            'PostgresService',
            task_definition=postgres_task,
            security_groups=[postgres_sg],
            cloud_map_options=ecs.CloudMapOptions(
                cloud_map_namespace=namespace,
                name='postgres-db',
                dns_record_type=servicediscovery.DnsRecordType.A
            ),
            cluster=cluster,
            desired_count=1
        )

        ###### API ######
        # I'm building on ARM, but ARM isn't available in GovCloud
        # so build for x86
        if os.environ.get('BUILD_ARM', None) is None:
            api_task = ecs.FargateTaskDefinition(
                self,
                'ApiTaskDefinition',
                cpu=256,
                memory_limit_mib=1024,
                runtime_platform=ecs.RuntimePlatform(
                    cpu_architecture=ecs.CpuArchitecture.X86_64
                )
            )
        else:
            api_task = ecs.FargateTaskDefinition(
                self,
                'ApiTaskDefinition',
                cpu=256,
                memory_limit_mib=1024,
                runtime_platform=ecs.RuntimePlatform(
                    cpu_architecture=ecs.CpuArchitecture.ARM64
                )
            )
        # Make sure to unzip the app into the containers/ directory
        # so it looks like containers/example-app-threat-db/data_api
        api_task.add_container(
            'ApiTaskContainer',
            image=ecs.ContainerImage.from_asset(
                'containers/example-app-threat-db/data_api'
            ),
            command=[
                'uvicorn', 'app.main:app', '--reload', '--host', '0.0.0.0', '--port', '8000'
            ],
            logging=ecs.AwsLogDriver(
                stream_prefix='threat-demo-api',
                log_group=logs.LogGroup(
                    self,
                    'LogGroupAPI',
                    retention=logs.RetentionDays.THREE_MONTHS
                )
            ),
            environment={
                'threat_db_host': f"{self.node.try_get_context('POSTGRES_SERVICE')}.{self.node.try_get_context('NAMESPACE')}",
                'threat_db_port': '5432'
            },
            secrets={
                'threat_db_pass': ecs.Secret.from_secrets_manager(postgres_password),
            },
            port_mappings=[
                ecs.PortMapping(
                    host_port=8000,
                    container_port=8000
                )
            ]
        )

        # Threat API service
        # Builds an Application Load Balancer, DNS names for the containers,
        # and a health check against HTTP port 8000
        # TO DO: Should be updated to use port 443 HTTPS with
        # a certificate from ACM
        api_service = ecs_patterns.ApplicationLoadBalancedFargateService(
            self,
            'ApiFargateService',
            security_groups=[api_sg],
            task_definition=api_task,
            cloud_map_options=ecs.CloudMapOptions(
                cloud_map_namespace=namespace,
                name=self.node.try_get_context('API_SERVICE'),
                dns_record_type=servicediscovery.DnsRecordType.A
            ),
            cluster=cluster,
            desired_count=2,
            public_load_balancer=False
        )
        # TO DO: This should go over HTTPS
        api_service.target_group.configure_health_check(
            enabled=True,
            port='8000',
            # is there a more appropriate path to check for health status?
            path='/vulnerabilities/',
            healthy_http_codes='200',
            healthy_threshold_count=2
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
        # TO DO: This should be updated to use TCP_TLS port 443
        ecs_alb_target_group = elbv2.NetworkTargetGroup(
            self,
            'EcsAlbTargetGroup',
            port=80,
            protocol=elbv2.Protocol.TCP,
            health_check=elbv2.HealthCheck(
                protocol=elbv2.Protocol.HTTP,
                healthy_threshold_count=2,
                path='/vulnerabilities/',
                unhealthy_threshold_count=2,
                interval=Duration.seconds(10),
                healthy_http_codes='200'
            ),
            targets=[
                elbv2_targets.AlbTarget(
                    alb=api_service.load_balancer,
                    port=80
                )
            ],
            vpc=vpc
        )
        # Create a listener on the NLB
        # TO DO: This should be port 443
        # TO DO: Create a certificate with ACM for use
        elbv2.NetworkListener(
            self,
            'NetworkLoadBalancerListener',
            load_balancer=nlb,
            port=80,
            default_target_groups=[ecs_alb_target_group]
        )

        # VPC link for API Gateway -> NLB integration
        vpc_link = apigw.VpcLink(
            self,
            'ApiGatewayVpcLink',
            description='VPC Link for API Gateway',
            targets=[nlb]
        )

        # Create the 'vulnerabilities' resource and method onto the REST API
        # that uses VPC link for the integration and Cognito for authorization
        vulnerabilities = rest_api.root.add_resource('vulnerabilities')
        put_vulnerabilities = vulnerabilities.add_resource('{id}')
        vulnerabilities.add_method(
            http_method='GET',
            integration=apigw.Integration(
                type=apigw.IntegrationType.HTTP_PROXY,
                integration_http_method='GET',
                uri=f'http://{api_service.load_balancer.load_balancer_dns_name}/vulnerabilities/',
                options=apigw.IntegrationOptions(
                    connection_type=apigw.ConnectionType.VPC_LINK,
                    vpc_link=vpc_link
                )
            ),
            authorizer=rest_authorizer,
            authorization_type=apigw.AuthorizationType.COGNITO
        )
        vulnerabilities.add_method(
            http_method='POST',
            integration=apigw.Integration(
                type=apigw.IntegrationType.HTTP_PROXY,
                integration_http_method='POST',
                uri=f'http://{api_service.load_balancer.load_balancer_dns_name}/vulnerabilities/',
                options=apigw.IntegrationOptions(
                    connection_type=apigw.ConnectionType.VPC_LINK,
                    vpc_link=vpc_link
                )
            ),
            authorizer=rest_authorizer,
            authorization_type=apigw.AuthorizationType.COGNITO
        )
        put_vulnerabilities.add_method(
            http_method='PUT',
            integration=apigw.Integration(
                type=apigw.IntegrationType.HTTP_PROXY,
                integration_http_method='PUT',
                uri=f'http://{api_service.load_balancer.load_balancer_dns_name}/' +
                    'vulnerabilities/{id}',
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
            'USERPOOLCLIENT',
            description='The user pool application client ID',
            value=user_pool_client.user_pool_client_id
        )
