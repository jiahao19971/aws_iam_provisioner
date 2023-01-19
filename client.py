import boto3

def assumeRole(session, account_id, region="ap-southeast-1", role_name="admin"):
    sts = session.client('sts')
    response = sts.assume_role(
            RoleArn=f"arn:aws:iam::{account_id}:role/{role_name}",
            RoleSessionName='admin',
        )

    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        assume_session = boto3.Session(
            aws_access_key_id=response['Credentials']['AccessKeyId'],
            aws_secret_access_key=response['Credentials']['SecretAccessKey'],
            aws_session_token=response['Credentials']['SessionToken'],
            region_name=region
        )

        iam = assume_session.client("iam")

        return iam

    return False

def get_account_list(client):
    accounts = client.list_accounts()
    account_ids = []
    for account in accounts['Accounts']:
        account_ids.append({"id": account['Id'], "name": account["Name"]})
    return account_ids

def get_sso_instance_arn(client):
    instance_info = client.list_instances()
    instance_arn = instance_info['Instances'][0]['InstanceArn']
    return instance_arn