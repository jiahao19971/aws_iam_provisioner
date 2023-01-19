import boto3, os, json
from dotenv import load_dotenv
from botocore.exceptions import ClientError
from main_enum import Mapper
from function import update_policy_attach_role
from client import assumeRole

load_dotenv()

profile = os.environ['MASTER_PROFILE']
session = boto3.Session(profile_name=profile)

try:
    role_name = os.environ["ROLE_NAME"]
except KeyError:
    role_name = "aws-iam-provisioner"

try:
    role_policy_name = os.environ["ROLE_POLICY_NAME"]
except KeyError:
    role_policy_name = "aws_iam_provisioner"

def create_role_permission(arn):
    role_trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Statement1",
                "Effect": "Allow",
                "Principal": {
                    "AWS": arn
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }

    return json.dumps(role_trust_policy)

def create_policy_permission():
    with open("role_policy.json", "r") as role_policy:
        policy = json.load(role_policy)
        
        return json.dumps(policy)


## This only applies if u have the master account already in assume role for all the other account mention 
with open("mapper.json", "r") as master:
    master_file = json.load(master)
    for account_name in master_file:
        all_account_id = master_file[account_name][Mapper.AccountID.value]

        policy_arn = f"arn:aws:iam::{all_account_id}:policy/{role_policy_name}"
        policy_str = create_policy_permission()

        iam = assumeRole(session, all_account_id)

        try:
            role = iam.get_role(
                RoleName=role_name
            )
            try:
                user_policy = json.loads(policy_str)
                update_policy_attach_role(iam, policy_arn, user_policy, role_policy_name, policy_str, role_name, account_name)

            except ClientError:
                iam_create = iam.create_policy(
                    PolicyName=role_policy_name, 
                    PolicyDocument=policy_str, 
                    Tags=[
                        {
                            'Key': 'AWSIAMProvisioner',
                            'Value': role_name
                        },
                        {
                            'Key': 'Environment',
                            'Value': account_name
                        },
                        {
                            'Key': 'Type',
                            'Value': "Policy"
                        },
                    ]
                )

                iam.attach_role_policy(
                    RoleName=role_name, 
                    PolicyArn=policy_arn
                )
                print('Custom Policy', role_policy_name, 'attached to role', role_name)
        except ClientError:
            print("create role")
            with open("users.json", "r") as master_iam_user:
                master_user = json.load(master_iam_user)

                role = iam.create_role(
                    RoleName=role_name,
                    AssumeRolePolicyDocument=create_role_permission(master_user['arn']),
                    Description='This role is use to be assume and have permission to IAM policy, role only to create, update and tag',
                    Tags=[
                        {
                            'Key': 'AWSIAMProvisioner',
                            'Value': role_name
                        },
                        {
                            'Key': 'Environment',
                            'Value': account_name
                        },
                        {
                            'Key': 'Type',
                            'Value': "Role"
                        },
                    ]
                )

                print("Role", role_name, "created")

                try:
                    user_policy = json.loads(policy_str)
                    update_policy_attach_role(iam, policy_arn, user_policy, role_policy_name, policy_str, role_name, account_name)
                except ClientError:
                    iam_create = iam.create_policy(
                        PolicyName=role_policy_name, 
                        PolicyDocument=policy_str, 
                        Tags=[
                            {
                                'Key': 'AWSIAMProvisioner',
                                'Value': role_name
                            },
                            {
                                'Key': 'Environment',
                                'Value': account_name
                            },
                            {
                                'Key': 'Type',
                                'Value': "Policy"
                            },
                        ]
                    )

                    iam.attach_role_policy(
                        RoleName=role_name, 
                        PolicyArn=policy_arn
                    )
                    print('Custom Policy', role_policy_name, 'attached to role', role_name)
            