import boto3, json, os
from dotenv import load_dotenv
from schema import mapper_schema, user_schema, validate_mapper_schema, validate_user_schema
from function import createPolicyVar,validateAction, handlePolicyChange, sharedValidation
from main_enum import RWRO, Mapper, PermissionSet, RequiredField
from client import assumeRole
from botocore.exceptions import ClientError
from slack_bot import SlackBot
from slackbot_enum import CHANGESTYPE
from empty import Empty
import logging

logging.basicConfig(format="%(asctime)s - %(levelname)s: %(message)s", level=logging.INFO)
load_dotenv()

try:
    region = os.environ['REGION']
except KeyError:
    region = "ap-southeast-1"

try:
    role_name = os.environ["ROLE_NAME"]
except KeyError:
    role_name = "aws-iam-provisioner"

try:
    organization = os.environ['ORGANIZATION']
except KeyError:
    organization = "Example"

user_file = RequiredField.USER.value
mapper_file = RequiredField.MAPPER.value

def main():
    logger = logging.getLogger("AWSIAMProvisioner")
    files = [f.name for f in os.scandir("./")]
    if mapper_file not in files and user_file not in files:
        message = json.dumps(f"Files not found")
        logger.error(message)
        return 
    with open(user_file, "r") as user_info:
        users_data = json.load(user_info)
        users_status, user_validate_error = validate_user_schema(user_schema, users_data)
        if ("slack-token" not in users_data) or ("slack-token" in users_data and users_data['slack-token'] == ""):
            logger.warning("No slack token was found, disabling slack notification")
            slack_bot = Empty()
        else:
            slack_bot = SlackBot(secret=users_data['slack-token'])
            if os.environ["CHECKOUT_BRANCH"] != RequiredField.BRANCH.value: 
                slack_bot = Empty()
            
        if users_status is False: 
            message = json.dumps(f"Failed to validate users with error {user_validate_error}")
            slack_bot.post_fail_message_to_slack("", user_file, message, CHANGESTYPE.VALIDATION.value)
            logger.error(message)
            return
        try:
            session = boto3.Session(
                aws_access_key_id=users_data['AccessKey']['AccessKeyId'],
                aws_secret_access_key=users_data['AccessKey']['SecretAccessKey'],
                region_name=region
            )

            account_folders = [ f.path for f in os.scandir("./") if f.is_dir() ]
            with open(mapper_file, "r") as master:
                master_file = json.load(master)
                mapper_status, mapper_validate_error = validate_mapper_schema(mapper_schema, master_file)
                if mapper_status is False: 
                    message = json.dumps(f"Failed to validate mapper with error {mapper_validate_error}")
                    slack_bot.post_fail_message_to_slack("", mapper_file, message, CHANGESTYPE.VALIDATION.value)
                    return

                for account in account_folders:
                    policiesFolders = [ f.path for f in os.scandir(f"{account}") if f.is_dir() ]

                    account_name = account.replace("./", "")

                    if account_name in master_file:
                        if len(policiesFolders) > 0:
                            for policies in policiesFolders:
                                account_id = master_file[account_name][Mapper.AccountID.value]

                                iam = assumeRole(session, account_id, region, role_name)

                                if iam is False:
                                    message = json.dumps(f"Failed to assume role for AWS IAM provisioner")
                                    slack_bot.post_fail_message_to_slack(account_name, "assumeRole", message, CHANGESTYPE.VALIDATION.value)
                                    logger.error(message)
                                    continue

                                if master_file[account_name]['custom']:
                                    rorw_folders = [ f.path for f in os.scandir(f"{policies}") if f.is_dir() ]

                                    for rorw in rorw_folders:
                                        rorw_name = rorw.replace(f"{policies}/", "")
                                        try:
                                            read_status = RWRO(rorw_name).name

                                            team_folders = [ f.path for f in os.scandir(f"{rorw}") if f.is_dir() ]

                                            for team in team_folders:
                                                team_name = team.replace(f"{rorw}/", "")

                                                role_id = master_file[account_name][Mapper.ACCOUNTINFO.value][read_status][Mapper.RoleID.value]

                                                user_json = [ f.path for f in os.scandir(f"{team}") if f.is_file() ]

                                                if len(user_json) > 0:
                                                    for user in user_json:
                                                        username = user.replace(f"{team}/", "").replace(".json", "")

                                                        with open(user, "r") as permissionset:
                                                            user_policy = json.load(permissionset)
                                                            policy_str = json.dumps(user_policy)

                                                            if read_status == RWRO.ReadOnly.name:
                                                                statement = user_policy[PermissionSet.Statement.value]
                                                                validate_status = validateAction(statement, user)

                                                                if validate_status is False:
                                                                    message = json.dumps(f"This is a read only access, please remove any read write access")
                                                                    slack_bot.post_fail_message_to_slack(account_name, user, message, CHANGESTYPE.VALIDATION.value)
                                                                    logger.error(message)
                                                                    continue

                                                            validated = sharedValidation(slack_bot, account_name, user, user_policy, role_id, policy_str)

                                                            if validated:
                                                                policy_name, policy_arn = createPolicyVar(organization, account_id, team_name.upper(), username.upper(), read_status)

                                                                role = master_file[account_name][Mapper.ACCOUNTINFO.value][read_status][Mapper.Role.value]
                                                                handlePolicyChange(organization, iam, user_policy, policy_str, policy_arn, policy_name, role, team_name, username, account_name, slack_bot)
                                        except ValueError as e:
                                            error = f"Found invalid: {e} on {user}"
                                            slack_bot.post_fail_message_to_slack(account_name, user, error, CHANGESTYPE.VALIDATION.value)
                                            logger.error(error)
                                            continue
                                else:
                                    role_id = master_file[account_name][Mapper.ACCOUNTINFO.value][Mapper.RoleID.value]
                                    team_folders = [ f.path for f in os.scandir(f"{policies}") if f.is_dir() ]

                                    for team in team_folders:
                                        team_name = team.replace(f"{policies}/", "")

                                        user_json = [ f.path for f in os.scandir(f"{team}") if f.is_file() ]

                                        if len(user_json) > 0:
                                            for user in user_json:
                                                username = user.replace(f"{team}/", "").replace(".json", "")

                                                with open(user, "r") as permissionset:
                                                    user_policy = json.load(permissionset)
                                                    policy_str = json.dumps(user_policy)
                                                    
                                                    validated = sharedValidation(slack_bot, account_name, user, user_policy, role_id, policy_str)

                                                    if validated:
                                                        policy_name, policy_arn = createPolicyVar(organization, account_id, team_name.upper(), username.upper())
                                                        role = master_file[account_name][Mapper.ACCOUNTINFO.value][Mapper.Role.value]

                                                        handlePolicyChange(organization, iam, user_policy, policy_str, policy_arn, policy_name, role, team_name, username, account_name, slack_bot)
        
        except ClientError as error:
            logger.error(error)
            slack_bot.post_fail_message_to_slack("", role_name, error, CHANGESTYPE.VALIDATION.value)
            return

        
if __name__ == '__main__':
    main()