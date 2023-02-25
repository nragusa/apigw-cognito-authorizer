
# Overview

This CDK application builds the following:

* A Cognito user pool and application client
* An API Gateway (REST) regional endpoint
* A `/hello` resource with `GET` method
* A Cognito authorizer associated to this resource
* A Lambda function that returns `{"message": "Hello World"}`

## Deployment

Using [AWS CloudFormation](https://aws.amazon.com/cloudformation/), deploy this [template.yml](templates/template.yml) in the region of your choice.

Once complete, be sure to click on the `Outputs` tab and save the values listed. In a terminal window, export the following from the `Outputs` tab to easily run commands in the subequent steps:

![outputs](images/outputs.png)

```bash
export USERPOOCLIENT=youruserpoolclientid
export USERPOOLID=youruserpoolid
export APIENDPOINT=yourAPIendpointURL
```

## Create a user

Before you can test the API Gateway endpoint, you first need to create a user in the Cognito user pool.

Using the [aws cli](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-welcome.html), run the following:

```bash
aws cognito-idp sign-up --client-id $USERPOOCLIENT  --username user@example.com --password 'ThisIsMyTemp0rary#' --user-attributes Name="email",Value="user@example.com"
```

Once you have created the user, you need to confirm the user in the user pool so that they may log in. See [step 3 here](https://docs.aws.amazon.com/cognito/latest/developerguide/signing-up-users-in-your-app.html#signing-up-users-in-your-app-and-confirming-them-as-admin).

## Generate a token

```bash
aws cognito-idp initiate-auth --auth-flow USER_PASSWORD_AUTH --auth-parameters USERNAME='user@example.com',PASSWORD='ThisIsMyTemp0rary#' --client-id $USERPOOCLIENT
```

Copy and export the value of `IdToken` that is returned.

```bash
export IDTOKEN=longstringofcharacters
```

Now test the API Gateway endpoint using curl:

```bash
curl -X GET $APIENDPOINT/hello -H "Authorization: $IDTOKEN"
```

You should get a JSON response similar to:

```bash
{"message": "Hello World"}
```
