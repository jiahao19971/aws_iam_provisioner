
# AWS IAM Provisioner
This repo tracks all the policies that we have in AWS and allocated user to their respective environment and permission

## Purpose of this script
The purpose of this repo is to allow
- Create Role and IDP
- Create Role Policies
- Attach and detach Role Policies

## Prerequisite
1. Make sure to have python >= 3.8.5
2. `pip install -r requirements.txt`
3. [Create an .env](#env)
4. To all the environment in AWS that you want it to run this script, create the [iam role](#rolepermission) that will have access .
5. Make sure to have [trust policy](#trustpolicy) setup for iam role 
6. Create a file called [mapper.json] (#mapperjson)
7. Create the environment directory:
   1. Inside each directory ensure that you have the IDP metadata
   2. Inside each directory ensure that there is a folder for policies
   3. Inside the policies directory ensure ensure that there is team 
   4. Inside each team, you can add in the permission.json which is the same as aws policies.
   5. For ReadWrite and Readonly access, in the policies directory create a ro and rw folder, then only proceed to policies [refer here](#Directories)

### .env
```diff
+ By default, this file should be stored in ./.env

+ required
MASTER_PROFILE=<the profile name created in ~/.aws/credentials>
+ required
ORGANIZATION=<Name that will be use as the first prefix of each role and policy>
+ not necessary 
REGION=<use to change the region of your aws account>

+ By default all variables below using the same naming: `aws-iam-provisioner`
+ not necessary
+ Allow you to customize the user name of the main account that you plan to assume role
MASTER_USERNAME=

+ not necessary 
+ Allow you to customize the policy name of the main account that you plan to grant the role access
MASTER_POLICY_NAME=

+ not necessary
+ Allow you to customize the role name for all environment in mapper.json which allow the master user to assume role on
ROLE_NAME=

+ not necessary
+ Allow you to customize the policy name for all environment in mapper.json which grants assume role permission
ROLE_POLICY_NAME=
```

### ~/.aws/credentials
```
[profile name]
aws_access_key_id=<access id>
aws_secret_access_key=<access secret key>
aws_session_token=<do no need it if it's a role access>
region=<which region>
```

### RolePermission
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "iam:CreatePolicy",
                "iam:CreatePolicyVersion",
                "iam:CreateRole",
                "iam:CreateSAMLProvider",
                "iam:Get*",
                "iam:List*",
                "iam:PutRolePolicy",
                "iam:TagPolicy",
                "iam:TagRole",
                "iam:TagSAMLProvider",
                "iam:UntagPolicy",
                "iam:UntagRole",
                "iam:UntagSAMLProvider",
                "iam:UpdateAssumeRolePolicy",
                "iam:UpdateRole",
                "iam:UpdateRoleDescription",
                "iam:UpdateSAMLProvider",
                "iam:DeletePolicyVersion"
            ],
            "Resource": "*"
        }
    ]
}
```

### TrustPolicy
```
{
    "Version": "2012-10-17",
    "Statement": [
        ...existing trust policy,
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": <arn of your iam role here>
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
```

### Mapper.json
```
This is the schema of the mapper: 
mapper_schema = {
    "type": "object",
    "patternProperties": {
        ".*": {
            "type": "object",
            "properties": {
                "AccountID": {"type": "string"},
                "custom": {"type": "boolean"},
            }
        }
    },
    "required": ["AccountID", "custom", "account_info"],
}

default_account_schema = {
    "type": "object",
    "properties": {
        "Role": {"type": "string"},
        "RoleArn": {"type": "string"},
        "RoleID": {"type": "string"},
        "SAML": {"type": "string"},
    },
    "required": ["Role", "RoleArn", "RoleID", "SAML"],
    "additionalProperties": False,
}

rwro_account_schema = {
    "type": "object",
    "properties": {
        "ReadWrite": {
            "type": "object",
            "properties": {
                "Role": {"type": "string"},
                "RoleArn": {"type": "string"},
                "RoleID": {"type": "string"},
                "SAML": {"type": "string"},
            },
            "required": ["Role", "RoleArn", "RoleID", "SAML"],
            "additionalProperties": False,
        },
        "ReadOnly": {
            "type": "object",
            "properties": {
                "Role": {"type": "string"},
                "RoleArn": {"type": "string"},
                "RoleID": {"type": "string"},
                "SAML": {"type": "string"},
            },
            "required": ["Role", "RoleArn", "RoleID", "SAML"],
            "additionalProperties": False,
        } 
    },
    "required": ["ReadWrite", "ReadOnly"],
    "additionalProperties": False,
}

```
The finalize version will look like this
```diff
# This is the default mapper needed. Further customization need to be change from policy_enum.py and other files to allow it to work.
{
    "<environment>": {
        "AccountID": <environment account id>,
        "custom": <boolean to allow rw/ro or disable>
# If custom is True 
        "account_info": {
            "ReadWrite": {
                "Role": <ROLE NAME>-<ENVIRONMENT>-ROLE-LIMITED-RW,
                "RoleArn": "arn:aws:iam::<environment account id>:role/<ROLE NAME>-<ENVIRONMENT>-ROLE-LIMITED-RW",
                "RoleID": <Role id to be auto added with iamCreateRole.py script>
                "SAML": <Insert by the user on the SAML metadata downloaded when creating the apps>
            },
            "ReadOnly": {
                "Role": <ROLE NAME>-<ENVIRONMENT>-ROLE-LIMITED-RO,
                "RoleArn": "arn:aws:iam::<environment account id>:role/<ROLE NAME>-<ENVIRONMENT>-ROLE-LIMITED-RO",
                "RoleID": <Role id to be auto added with iamCreateRole.py script>
                "SAML": <Insert by the user on the SAML metadata downloaded when creating the apps>
            },
        }
# If custom is False
        "account_info": {
            "Role": <ROLE NAME>-<ENVIRONMENT>-ROLE-LIMITED,
            "RoleArn": "arn:aws:iam::<environment account id>:role/<ROLE NAME>-<ENVIRONMENT>-ROLE-LIMITED",
            "RoleID": <Role id to be auto added with iamCreateRole.py script>
            "SAML": <Insert by the user on the SAML metadata downloaded when creating the apps>
        }
    },
    ...other environment,
}
```

### users.json
```
{
    "username": <name of iam user>,
    "userid": <role id of the user>,
    "arn": <arn of the user>,
    "AccessKey": {
        "AccessKeyId": <iam user access key>,
        "SecretAccessKey": <iam user secret key>
    },
    "slack-token": <optional>
}
```

### To generate the policy follow here.
- https://awspolicygen.s3.amazonaws.com/policygen.html

## How to use the script
First create the iam user for the main account that we will be using it to assume role in different environment account.
Do not that this can be skip if u already have the user and access key setup. Just make sure to create a file called [users.json](#usersjson) and add in the information needed
Make sure that this is run just once or else each time u run, it will generate a new access id and secret.
`python init.py`

After running the `init.py`, a new file will be generated called, [users.json](#usersjson)

If you need to create role in different environment that will be use by assume user. Make sure that the user have permission to all the account of else the script will failed.
In each of your role that your user planned to assume must have the [trustpolicy](#trustpolicy)
!This might not be needed if u already have the role ready to be assume
`python masterCreateRole.py` 


Then we can start to create the iam role and idp 
before running the script, ensure that the [SAML metadata](#directories) are added to the correct destination, and have inserted the name into the [mapper.json](#mapperjson)
Then run:
`python createRole.py`
This will help to add in any missing information that are needed[mapper.json](#mapperjson)

Once you created the role and idp, run 
`python main.py`

## Directories
```
project
|    .env
|    .gitignore
|    client.py
|    createRole.py
|    mapper.json
|    masterCreateRole.py
|    main_enum.py
|    main.py
|    function.py
│    README.md
|    requirements.txt
|    role_policy.json
|    empty.py
|    slack_bot.py
|    slackbot_enum.py
|    schema.py
|    users.json (must be self created or use init script)
|─── <environment>
|    |    policies
|    |    └─── <team name>
|    |          └───<user>.json
|    └─── <SAML metadata>.xml
└─── <environment with custom>
     |    policies
     |    |─── rw
     |    |     └─── <team name>
     |    |          └───<user>.json     
     |    └─── ro
     |          └─── <team name>
     |               └───<user>.json
     └─── <SAML metadata>.xml
```

## Note
- The Role and IDP name is being hardcoded with ROLE-LIMITED and IDP-LIMITED as the suffix. There is no customization for now
- The ReadOnly and ReadWrite is being hardcoded with ROLE-LIMITED-RO, ROLE-LIMITED-RW and IDP-LIMITED-RO, IDP-LIMITED-RW as the suffix.
