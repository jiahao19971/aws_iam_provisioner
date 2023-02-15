import boto3, os, json, logging
from dotenv import load_dotenv
from botocore.exceptions import ClientError
from main_enum import Mapper
from function import update_policy_attach_user
from schema import validate_mapper_schema, mapper_schema

load_dotenv()

logging.basicConfig(format="%(asctime)s - %(levelname)s: %(message)s", level=logging.INFO)
logger = logging.getLogger("AWSIAMProvisioner")

profile = os.environ['MASTER_PROFILE']
session = boto3.Session(profile_name=profile)
sts = session.client("sts")
master_account_id = sts.get_caller_identity()
master_account_id = master_account_id['Account']

iam = session.client("iam")

def createUserPermissionBoundary(role):
    permission = {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": role
        }
    }

    return json.dumps(permission)

try:
    master_username = os.environ["MASTER_USERNAME"]
except KeyError:
    master_username = "aws-iam-provisioner"

try:
    iam_role = os.environ["ROLE_NAME"]
except KeyError:
    iam_role = "aws-iam-provisioner"

try:
    master_policy = os.environ["MASTER_POLICY_NAME"]
except KeyError:
    master_policy = "aws-iam-provisioner"

def write_to_users(field, data):
    with open("users.json", "r") as userFile:
        users = json.load(userFile)
        users.update(
            [
                (field, data)
            ]
        )

    with open("users.json", "w") as writeUsers:
        json.dump(users, writeUsers, indent=4)
        logger.info("Updated users.json with the latest data")

with open("mapper.json", "r") as master:
    policy_arn = f"arn:aws:iam::{master_account_id}:policy/{master_policy}"
    master_file = json.load(master)

    mapper_status = validate_mapper_schema(mapper_schema, master_file)

    arn = []
    for account_name in master_file:
        all_account_id = master_file[account_name][Mapper.AccountID.value]

        arn.append(f"arn:aws:iam::{all_account_id}:role/{iam_role}")

    policy_str = createUserPermissionBoundary(arn)

    user_policy = json.loads(policy_str)

    if mapper_status:
        try:
            iam_user = iam.get_user(
                UserName=master_username
            )
            try:
                write_to_users("username", iam_user['User']['UserName'])
                write_to_users("arn", iam_user['User']['Arn'])
                write_to_users("userid", iam_user['User']['UserId'])
            except Exception:
                user_data = {
                    "username": iam_user['User']['UserName'],
                    "userid": iam_user['User']['UserId'],
                    "arn": iam_user['User']['Arn'],
                }

                with open("users.json", "w") as userfile:
                    json.dump(user_data, userfile, indent=4)

            try:
                logger.info("Policy exist")
                iam_policy = iam.get_policy(
                    PolicyArn=policy_arn
                )
                
                update_policy_attach_user(iam, policy_arn, user_policy, master_policy, policy_str, master_username)

            except ClientError:
                logger.info("Create IAM Policy")

                policy = iam.create_policy(
                            PolicyName=master_policy,
                            PolicyDocument=policy_str,
                            Description='This is the policy created for aws iam provisioner to assume role in different accounts',
                            Tags=[
                                {
                                    'Key': "AWSIAMProvisioner",
                                    'Value': master_policy
                                },
                            ]
                        )
                
                update_policy_attach_user(iam, policy_arn, user_policy, master_policy, policy_str, master_username)
                
        except ClientError:
            logger.info(f"create user: {master_username}")
            users = iam.create_user(
                UserName=master_username,
                Tags=[
                    {
                        'Key': 'AWSIAMProvisioner',
                        'Value': master_username
                    },
                ]
            )

            try:
                write_to_users("username", users['User']['UserName'])
                write_to_users("arn", users['User']['Arn'])
                write_to_users("userid", users['User']['UserId'])
            except Exception:
                user_data = {
                    "username": users['User']['UserName'],
                    "userid": users['User']['UserId'],
                    "arn": users['User']['Arn'],
                }

            update_policy_attach_user(iam, policy_arn, user_policy, master_policy, policy_str, master_username)
        finally:
            with open("users.json", "r") as userfile:
                users = json.load(userfile)
                if "AccessKey" not in users:
                    if "AccessKeyId" not in users["AccessKey"]or "SecretAccessKey" not in users["AccessKey"]:
                        if users["AccessKey"]["AccessKeyId"] == "" or users["AccessKey"]["SecretAccessKey"] == "":
                            logger.info("Create access key")
                            secret_key = iam.create_access_key(
                                    UserName=master_username
                                )

                            keys_data = {
                                'UserName': secret_key["AccessKey"]["UserName"],
                                'AccessKeyId': secret_key["AccessKey"]["AccessKeyId"],
                                'Status': secret_key["AccessKey"]["Status"],
                                'SecretAccessKey': secret_key["AccessKey"]["SecretAccessKey"],
                            }

                            users["AccessKey"] = keys_data

                            with open("users.json", "w") as userWriter:
                                json.dump(users, userWriter, indent=4)
                                
                else:
                    logger.info("completed with existing aws access key and secret")




