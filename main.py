import boto3, json, os
from dotenv import load_dotenv
from schema import policy_schema, mapper_schema, user_schema, validate_policy_schema, validate_mapper_schema, validate_user_schema
from function import createPolicyVar,validateAction, validate_role_id, handlePolicyChange
from main_enum import RWRO, Policies, Mapper, PermissionSet
from client import assumeRole
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

with open("users.json", "r") as user_info:
    users_data = json.load(user_info)
    users_status = validate_user_schema(user_schema, users_data)
    if users_status is True: 
        session = boto3.Session(
            aws_access_key_id=users_data['AccessKey']['AccessKeyId'],
            aws_secret_access_key=users_data['AccessKey']['SecretAccessKey'],
            region_name=region
        )

        account_folders = [ f.path for f in os.scandir("./") if f.is_dir() ]
        with open("mapper.json", "r") as master:
            master_file = json.load(master)
            mapper_status = validate_mapper_schema(mapper_schema, master_file)
            if mapper_status is True:
                for account in account_folders:
                    policiesFolders = [ f.path for f in os.scandir(f"{account}") if f.is_dir() ]

                    account_name = account.replace("./", "")

                    if account_name in master_file:
                        if len(policiesFolders) > 0:
                            for policies in policiesFolders:
                                account_id = master_file[account_name][Mapper.AccountID.value]

                                iam = assumeRole(session, account_id, region, role_name)

                                if iam:
                                    if master_file[account_name]['custom']:
                                        rorw_folders = [ f.path for f in os.scandir(f"{policies}") if f.is_dir() ]

                                        for rorw in rorw_folders:
                                            rorw_name = rorw.replace(f"{policies}/", "")
                                            try:
                                                read_status = RWRO(rorw_name).name

                                                team_folders = [ f.path for f in os.scandir(f"{rorw}") if f.is_dir() ]

                                                for team in team_folders:
                                                    team_name = team.replace(f"{rorw}/", "")

                                                    role_id = master_file[account_name]["account_info"][read_status][Mapper.RoleID.value]

                                                    userJson = [ f.path for f in os.scandir(f"{team}") if f.is_file() ]

                                                    if len(userJson) > 0:
                                                        for user in userJson:
                                                            username = user.replace(f"{team}/", "").replace(".json", "")

                                                            with open(user, "r") as permissionset:
                                                                user_policy = json.load(permissionset)

                                                                policy_status = validate_policy_schema(policy_schema, user_policy, user)

                                                                if policy_status is False:
                                                                    break

                                                                policy_str = json.dumps(user_policy)

                                                                statement = user_policy[PermissionSet.Statement.value]

                                                                validate_sid = [sid[Policies.Sid.value] for sid in statement if Policies.Sid.value in sid]

                                                                if(len(set(validate_sid)) != len(validate_sid)):
                                                                    print("Problem with the Sid:", user)
                                                                    break

                                                                if read_status == RWRO.ReadOnly.name:
                                                                    validate_status = validateAction(statement, user)

                                                                    if validate_status is False:
                                                                        break
                                                                policy_name, policy_arn = createPolicyVar(organization, account_id, team_name.upper(), username.upper(), read_status)

                                                                role = master_file[account_name]["account_info"][read_status][Mapper.Role.value]

                                                                validate_condition = validate_role_id(statement, role_id, user)

                                                                if validate_condition is False:
                                                                    break

                                                                handlePolicyChange(organization, iam, user_policy, policy_str, policy_arn, policy_name, role, team_name, username, account_name)
                                            except ValueError as e:
                                                print("Found invalid:", e, "on", user)
                                                break
                                    else:
                                        role_id = master_file[account_name]["account_info"][Mapper.RoleID.value]
                                        team_folders = [ f.path for f in os.scandir(f"{policies}") if f.is_dir() ]

                                        for team in team_folders:
                                            team_name = team.replace(f"{policies}/", "")

                                            userJson = [ f.path for f in os.scandir(f"{team}") if f.is_file() ]

                                            if len(userJson) > 0:
                                                for user in userJson:
                                                    username = user.replace(f"{team}/", "").replace(".json", "")

                                                    with open(user, "r") as permissionset:
                                                        user_policy = json.load(permissionset)

                                                        policy_status = validate_policy_schema(policy_schema, user_policy, user)
                                                            
                                                        if policy_status is False:
                                                            break
                                                        
                                                        policy_str = json.dumps(user_policy)

                                                        statement = user_policy[PermissionSet.Statement.value]

                                                        validate_sid = [sid[Policies.Sid.value] for sid in statement if Policies.Sid.value in sid]

                                                        if(len(set(validate_sid)) != len(validate_sid)):
                                                            print("Problem with the Sid:", user)
                                                            break

                                                        validate_condition = validate_role_id(statement, role_id, user)

                                                        if validate_condition is False:
                                                            break

                                                        policy_name, policy_arn = createPolicyVar(organization, account_id, team_name.upper(), username.upper())
                                                        role = master_file[account_name]["account_info"][Mapper.Role.value]

                                                        handlePolicyChange(organization, iam, user_policy, policy_str, policy_arn, policy_name, role, team_name, username, account_name)
                                                        