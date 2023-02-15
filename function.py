from botocore.exceptions import ClientError
import re, json, logging
from main_enum import Policies, PermissionSet, ConditionMust, ConditionUserID
from schema import policy_schema, validate_policy_schema
from slackbot_enum import CHANGESTYPE

logger = logging.getLogger("AWSIAMProvisioner")

def createPolicyVar(organization, account_id, team_name, username, rwro = False):
    policy_name = f"{organization.upper()}-{team_name.upper()}-{username.upper()}-POLICY"                                        
    policy_arn = f"arn:aws:iam::{account_id}:policy/{policy_name}"
    if rwro:
        if rwro == "ReadOnly":
            policy_name = f"{organization.upper()}-{team_name.upper()}-{username.upper()}-POLICY-RO"                                        
        else:
            policy_name = f"{organization.upper()}-{team_name.upper()}-{username.upper()}-POLICY-RW"                                        
        policy_arn = f"arn:aws:iam::{account_id}:policy/{policy_name}"
    
    return policy_name, policy_arn

def createPolicy(organization, iam, policy_name, policy_str, team_name, username, account_name):
    tags = [
        {
            'Key': organization,
            'Value': f"{team_name.upper()}-{username.upper()}"
        },
        {
            'Key': 'Environment',
            'Value': account_name.upper()
        },
        {
            'Key': 'Type',
            'Value': 'Policy'
        },
    ]
    iam_create = iam.create_policy(
        PolicyName=policy_name, 
        PolicyDocument=policy_str, 
        Tags=tags
    )

    if iam_create:
        message = f'Custom Policy {policy_name} created.'
        logger.info(message)
        return iam_create
    else:
        return False

def attachRoleToPolicy(iam, role, policy_arn, policy_name):
    iam.attach_role_policy(
        RoleName=role, 
        PolicyArn=policy_arn
    )
    message = f'Custom Policy {policy_name} attached to role {role}'
    logger.info(message)

def attachPolicyToUser(iam, username, policy_arn, policy_name):
    iam.attach_user_policy(
        UserName=username,
        PolicyArn=policy_arn
    )
    message = f'Custom Policy {policy_name} attached to user {username}'
    logger.info(message)

def detachRoleToPolicy(iam, role, policy_arn, policy_name):
    iam.detach_role_policy(
        RoleName=role,
        PolicyArn=policy_arn
    )
    message = f"Detaching policy {policy_name} from role {role}"
    logger.info(message)

def deletePolicy(iam, policy_arn, policy_name):
    iam.delete_policy(
        PolicyArn=policy_arn
    )
    message = f"Deleted policy {policy_name}"
    logger.info(message)

def deleteMinPolicyVersion(iam, policy_version, policy_arn, policy_name):
    policy_min_version = min(policy_version)

    version_to_delete = f"v{policy_min_version}"

    logger.info(f"Deleting {policy_name} {version_to_delete}")

    iam.delete_policy_version(
        PolicyArn=policy_arn,
        VersionId=version_to_delete
    )

    message = f"Deleted policy version {version_to_delete} for {policy_name}"
    logger.info(message)

def createPolicyVersion(iam, policy_arn, policy_str, policy_name, role):
    iam.create_policy_version(
        PolicyArn=policy_arn,
        PolicyDocument=policy_str,
        SetAsDefault=True
    )
    message = f"Updated policy {policy_name} on role {role}"
    logger.info(message)

def getCurrentPolicyVersion(iam, all_policy_version, policy_arn):
    all_policy_version_without_default = [int(plc["VersionId"].replace("v", "")) for plc in all_policy_version["Versions"] if plc["IsDefaultVersion"] is False]
    default_version = [plc["VersionId"] for plc in all_policy_version["Versions"] if plc["IsDefaultVersion"] is True][0]
    
    getPolicy = iam.get_policy_version(
        PolicyArn=policy_arn,
        VersionId=default_version
    )

    current_policy_version = getPolicy["PolicyVersion"]["Document"]

    return all_policy_version_without_default, current_policy_version

def listAttachedRolePolicies(iam, role, policy_name):
    list_attached_role = iam.list_attached_role_policies(RoleName=role)
    list_attached_role = [policy_names["PolicyName"] for policy_names in list_attached_role["AttachedPolicies"] if policy_names["PolicyName"] == policy_name]

    return list_attached_role

def listAttachedUserPolicies(iam, user, policy_name):
    list_attached_user = iam.list_attached_user_policies(UserName=user)
    list_attached_user = [policy_names["PolicyName"] for policy_names in list_attached_user["AttachedPolicies"] if policy_names["PolicyName"] == policy_name]

    return list_attached_user

def validateAction(statement, user):
    validate_action = [sid[Policies.Action.value] for sid in statement]
    validate_status = True
    for action in validate_action:
        if type(action) == list:
            check = [ act for act in action if re.search("(.*):(\\*|Delete|Update|Put)", act) != None ]
            if len(check) > 0:
                error = f"Found (*|Delete|Update|Put) in Permission set {check} in {user}"
                logger.error(error)
                validate_status = False 
                break                                                                       
        else:
            if re.search("(.*):(\\*|Delete|Update|Put)", action) != None:
                error = f"Found (*|Delete|Update|Put) in Permission set {action} in {user}"
                logger.error(error)
                validate_status = False
                break

    return validate_status

def validate_role_id(statement, role_id, user):
    validate_condition = True
    for state in statement:
        if Policies.Condition.value not in state:
            error = "Condition not found in policies, please add it in for", user
            logger.error(error)
            validate_condition = False
            break
        
        conditions = state[Policies.Condition.value][ConditionMust.StringEqualsIgnoreCase.value][ConditionUserID.UserID.value]

        state_validate = [condition for condition in conditions if re.search(f"{role_id}:(.*)",condition) == None]

        if len(state_validate) > 0:
            error = "suppose", role_id, "but received", state_validate, "for", user
            logger.error(error)
            validate_condition = False
            break

    return validate_condition

def update_policy_attach_user(iam, policy_arn, user_policy, user_policy_name, policy_str, user_name):
    all_policy_version = iam.list_policy_versions(PolicyArn=policy_arn)
    all_policy_version_without_default, currentPolicyVersion = getCurrentPolicyVersion(iam, all_policy_version, policy_arn)

    if currentPolicyVersion != user_policy:
        logger.info("update needed")
        if len(all_policy_version_without_default) == 4:
            deleteMinPolicyVersion(iam, all_policy_version_without_default, policy_arn, user_policy_name)

        createPolicyVersion(iam, policy_arn, policy_str, user_policy_name, user_name)

    list_attached_role = listAttachedUserPolicies(iam, user_name, user_policy_name)

    if len(list_attached_role) == 0:
        attachPolicyToUser(iam, user_name, policy_arn, user_policy_name)
    else:
        message = f'No changes/attached needed for {user_policy_name}'
        logger.info(message)

def update_policy_attach_role(iam, policy_arn, user_policy, role_policy_name, policy_str, role_name, account_name, slack_bot):
    all_policy_version = iam.list_policy_versions(PolicyArn=policy_arn)
    all_policy_version_without_default, currentPolicyVersion = getCurrentPolicyVersion(iam, all_policy_version, policy_arn)

    if currentPolicyVersion != user_policy:
        message = f'Update needed for {role_policy_name} in {account_name}'
        logger.info(message)
        if len(all_policy_version_without_default) == 4:
            policy_min_version = min(all_policy_version_without_default)
            deleteMinPolicyVersion(iam, all_policy_version_without_default, policy_arn, role_policy_name)
            slack_bot.post_success_message_to_slack(account_name, role_policy_name, f"Successfully deleted policy {role_policy_name} v{policy_min_version}", CHANGESTYPE.DELETE.value)

        createPolicyVersion(iam, policy_arn, policy_str, role_policy_name, role_name)
        slack_bot.post_success_message_to_slack(account_name, role_policy_name, f"Successfully updated policy {role_policy_name}", CHANGESTYPE.UPDATE.value)

    list_attached_role = listAttachedRolePolicies(iam, role_name, role_policy_name)
    
    if len(list_attached_role) == 0:
        attachRoleToPolicy(iam, role_name, policy_arn, role_policy_name)
        slack_bot.post_success_message_to_slack(account_name, role_policy_name, f"Successfully attached policy {role_policy_name} to role {role_name}", CHANGESTYPE.UPDATE.value)
    else:
        message = f'No changes/attached needed for {role_policy_name} in {account_name}'
        logger.info(message)

def handlePolicyChange(
    organization, 
    iam, 
    user_policy, 
    policy_str, 
    policy_arn, 
    policy_name, 
    role, 
    team_name, 
    username, 
    account_name,
    slack_bot
):
    if len(user_policy[PermissionSet.Statement.value]) > 0:
        try:
            update_policy_attach_role(iam, policy_arn, user_policy, policy_name, policy_str, role, account_name, slack_bot)
        except ClientError:
            try:
                slack_bot.post_success_message_to_slack(account_name, policy_name, f"Successfully create policy {policy_name}", CHANGESTYPE.CREATE.value)
                iam_create = createPolicy(organization, iam, policy_name, policy_str, team_name, username, account_name)
                if iam_create:
                    slack_bot.post_success_message_to_slack(account_name, policy_name, f"Successfully attached policy {policy_name}", CHANGESTYPE.UPDATE.value)
                    attachRoleToPolicy(iam, role, policy_arn, policy_name)

            except ClientError as e:
                error = f"Failed to create policy in {account_name} for {policy_name} with error message {e}" 
                logger.error(error)
                slack_bot.post_fail_message_to_slack(account_name, policy_name, message, CHANGESTYPE.CREATE.value)
    else:
        try:
            policy = iam.list_policy_versions(PolicyArn=policy_arn)
            list_attached_role = listAttachedRolePolicies(iam, role, policy_name)
    
            if len(list_attached_role) != 0:
                message = f"Need to detach policy {policy_name} in {account_name}"
                logger.info(message)
                detachRoleToPolicy(iam, role, policy_arn, policy_name)
                slack_bot.post_success_message_to_slack(account_name, policy_name, f"Successfully detached policy {policy_name}", CHANGESTYPE.UPDATE.value)

            if policy:
                deletePolicy(iam, policy_arn, policy_name)
                slack_bot.post_success_message_to_slack(account_name, policy_name, f"Successfully deleted policy {policy_name}", CHANGESTYPE.DELETE.value)
                
        except ClientError as error:
            logger.error(error)
            
            logger.warning("Skipping since policy does not exist")

def sharedValidation(slack_bot, account_name, user, user_policy, role_id):
    status = []
    policy_status, policy_validate_error = validate_policy_schema(policy_schema, user_policy, user)
    status.append(policy_status)
    if policy_status is False:
        message = json.dumps(f"Failed to validate policy with error {policy_validate_error}")
        slack_bot.post_fail_message_to_slack(account_name, user, message, "validation")
        logger.error(message)

    statement = user_policy[PermissionSet.Statement.value]

    validate_sid = [sid[Policies.Sid.value] for sid in statement if Policies.Sid.value in sid]
    sid_length = len(set(validate_sid)) == len(validate_sid)
    status.append(sid_length)

    if sid_length is False:
        message = f"Problem with the Sid: {user}"
        slack_bot.post_fail_message_to_slack(account_name, user, message, "validation")
        logger.error(message)
        

    validate_condition = validate_role_id(statement, role_id, user)
    status.append(validate_condition)
    if validate_condition is False:
        message = f"Incorrect role_id for user: {user}"
        slack_bot.post_fail_message_to_slack(account_name, user, message, "validation")
        logger.error(message)

    if False in set(status): return False
    else: return True