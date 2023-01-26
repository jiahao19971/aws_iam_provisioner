import boto3, json, os
from dotenv import load_dotenv
from botocore.exceptions import ClientError
from main_enum import Mapper, RWRO
from client import assumeRole
from schema import mapper_schema, user_schema, validate_mapper_schema, validate_user_schema
load_dotenv()

try:
    organization = os.environ['ORGANIZATION']
except KeyError:
    organization = "Example"

try:
    region = os.environ['REGION']
except KeyError:
    region = "ap-southeast-1"

try:
    assume_role_name = os.environ["ROLE_NAME"]
except KeyError:
    assume_role_name = "aws-iam-provisioner"

def createMapperData(role, saml):
    data = {
        "Role": role['Role']['RoleName'],
        "RoleArn": role['Role']['Arn'],
        "RoleID": role['Role']['RoleId'],
        "SAML": saml
    }

    return data

def create_assume_role(account_id, idp):
    assume_role = json.dumps({
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {
                                "Federated": f"arn:aws:iam::{account_id}:saml-provider/{idp}"
                            },
                            "Action": "sts:AssumeRoleWithSAML",
                            "Condition": {
                                "StringEquals": {
                                    "SAML:aud": "https://signin.aws.amazon.com/saml"
                                }
                            }
                        }
                    ]
                })

    return assume_role

def write_to_custom_mapper(account_name, write_data, read_data):
    with open("mapper.json", "r") as Masterfile:
        master = json.load(Masterfile)
        if read_data == None:
            read = master[account_name][Mapper.ACCOUNTINFO.value][RWRO.ReadOnly.name]
            write = write_data
        else:
            read = read_data
            write = master[account_name][Mapper.ACCOUNTINFO.value][RWRO.ReadWrite.name]
        master.update(
            [
                (
                    account_name, {
                        Mapper.AccountID.value: master[account_name]['AccountID'],
                        Mapper.CUSTOM.value: True,
                        Mapper.ACCOUNTINFO.value: {
                            RWRO.ReadWrite.name: write,
                            RWRO.ReadOnly.name: read
                        }
                    }
                )
            ]
        )

        with open("mapper.json", "w") as writeMaster:
            json.dump(master, writeMaster, indent=4)
            print("Updated mapper.json with the latest data")

def write_to_other_mapper(account_name, data):
    with open("mapper.json", "r") as Masterfile:
        master = json.load(Masterfile)
        master.update(
            [
                (account_name, data)
            ]
        )

        with open("mapper.json", "w") as writeMaster:
            json.dump(master, writeMaster, indent=4)
            print("Updated mapper.json with the latest data")

def createTags(organization, account_name, account_properties = ""):
    if account_properties == "":
        tags = [
            {
                'Key': organization,
                'Value': "Limited Access"
            },
            {
                'Key': 'Environment',
                'Value': account_name.capitalize()
            },
            {
                'Key': 'Type',
                'Value': 'Role'
            },
        ]
    else:
        text = " ".join(account_properties.split("Read"))
        tags = [
                {
                        'Key': organization,
                        'Value': f"Limited Read{text} Access"
                    },
                    {
                        'Key': 'Environment',
                        'Value': account_name.capitalize()
                    },
                    {
                        'Key': 'Type',
                        'Value': 'Role'
                    }
                ]
    return tags

with open("users.json", "r") as user_info:
    users_data = json.load(user_info)
    users_status = validate_user_schema(user_schema, users_data)
    if users_status is True: 
        session = boto3.Session(
            aws_access_key_id=users_data['AccessKey']['AccessKeyId'],
            aws_secret_access_key=users_data['AccessKey']['SecretAccessKey'],
            region_name=region
        ) 

        with open("mapper.json", "r") as Masterfile:
            master = json.load(Masterfile)
            mapper_status = validate_mapper_schema(mapper_schema, master)
            if mapper_status is True:
                for account_name in master:
                    account_id = master[account_name][Mapper.AccountID.value]

                    iam = assumeRole(session, account_id, region, assume_role_name)

                    if iam:
                        if master[account_name]["custom"]:
                            for account_properties in master[account_name][Mapper.ACCOUNTINFO.value]:
                                if account_properties == RWRO.ReadOnly.name or account_properties == RWRO.ReadWrite.name:
                                    role_name = f"{master[account_name][Mapper.ACCOUNTINFO.value][account_properties][Mapper.Role.value]}"
                                    if account_properties == RWRO.ReadOnly.name:
                                        idp_name = f"{organization.upper()}-{account_name.upper()}-IDP-LIMITED-{RWRO.ReadOnly.value.upper()}"
                                        file_name = f"./{account_name}/{master[account_name][Mapper.ACCOUNTINFO.value][account_properties][Mapper.SAML.value]}.xml"
                                    else:
                                        idp_name = f"{organization.upper()}-{account_name.upper()}-IDP-LIMITED-{RWRO.ReadWrite.value.upper()}"
                                        file_name = f"./{account_name}/{master[account_name][Mapper.ACCOUNTINFO.value][account_properties][Mapper.SAML.value]}.xml"
                                    try:
                                        role = iam.get_role(
                                            RoleName=role_name
                                        ) 
                                        data = createMapperData(role, master[account_name][Mapper.ACCOUNTINFO.value][account_properties][Mapper.SAML.value])

                                        if account_properties == RWRO.ReadOnly.name:
                                            read_data = data
                                            write_data = None
                                        else:
                                            read_data = None
                                            write_data = data

                                        write_to_custom_mapper(account_name, write_data, read_data)

                                        # Tag role if it is not being tag
                                        role_tag = iam.list_role_tags(
                                            RoleName=role_name,
                                        )

                                        if len(role_tag['Tags']) == 0:
                                            
                                            tag_iam_role = iam.tag_role(
                                                RoleName=role_name,
                                                Tags=createTags(organization, account_name, account_properties)
                                            )

                                            print("Successfully tag role", tag_iam_role)
                                    except ClientError:
                                        try:
                                            iam.get_saml_provider(
                                                SAMLProviderArn=f"arn:aws:iam::{account_id}:saml-provider/{idp_name}"
                                            )
                                        except ClientError:
                                            print("Create IDP")
                                            with open(file_name, 'r') as metadata:
                                                metadata = metadata.read()
                                                response = iam.create_saml_provider(Name=idp_name, SAMLMetadataDocument=metadata)
                                            print("IDP", idp_name, "created.")

                                        finally:
                                            assume_ro_role = create_assume_role(master[account_name][Mapper.AccountID.value], idp_name)
                                            role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=assume_ro_role)
                                            print('Role', role_name, 'created.')

                                            data = createMapperData(role, master[account_name][Mapper.ACCOUNTINFO.value][account_properties][Mapper.SAML.value])

                                            if account_properties == RWRO.ReadOnly.name:
                                                read_data = data
                                                write_data = None
                                            else:
                                                read_data = None
                                                write_data = data

                                            write_to_custom_mapper(account_name, write_data, read_data)
                        else:
                            role_name = f"{master[account_name][Mapper.ACCOUNTINFO.value][Mapper.Role.value]}"
                            idp_name = f"{organization.upper()}-{account_name.upper()}-IDP-LIMITED"
                            try:
                                role = iam.get_role(
                                    RoleName=role_name
                                ) 

                                data = {
                                    Mapper.AccountID.value: master[account_name]['AccountID'],
                                    Mapper.CUSTOM.value: False,
                                    Mapper.ACCOUNTINFO.value: createMapperData(role, master[account_name][Mapper.ACCOUNTINFO.value][Mapper.SAML.value])
                                }

                                write_to_other_mapper(account_name, data)

                                role_tag = iam.list_role_tags(
                                    RoleName=role_name,
                                )

                                if len(role_tag['Tags']) == 0:
                                    tag_iam_role = iam.tag_role(
                                        RoleName=role_name,
                                        Tags=createTags(organization, account_name)
                                    )
                                    print("Successfully tag role", tag_iam_role)
                            except ClientError:
                                try:
                                    iam.get_saml_provider(
                                        SAMLProviderArn=f"arn:aws:iam::{account_id}:saml-provider/{idp_name}"
                                    )
                                except ClientError:
                                    print("Create IDP")
                                    
                                    with open(f"./{account_name}/{master[account_name][Mapper.ACCOUNTINFO.value][Mapper.SAML.value]}.xml", 'r') as metadata:
                                        metadata = metadata.read()
                                        response = iam.create_saml_provider(Name=idp_name, SAMLMetadataDocument=metadata)
                                    print("IDP", idp_name, "created.")
                                finally:
                                    print("Create Role")
                                    assume_role = create_assume_role(master[account_name][Mapper.AccountID.value], idp_name)
                                    role = iam.create_role(
                                        RoleName=role_name,
                                        AssumeRolePolicyDocument=assume_role,
                                        Tags=createTags(organization, account_name)
                                    )
                                    print('Role', role_name, 'created.')

                                    data = {
                                        Mapper.AccountID.value: master[account_name]['AccountID'],
                                        Mapper.CUSTOM.value: False,
                                        Mapper.ACCOUNTINFO.value: createMapperData(role, master[account_name][Mapper.ACCOUNTINFO.value][Mapper.SAML.value])
                                    }

                                    write_to_other_mapper(account_name, data)