from jsonschema import Draft7Validator
from main_enum import Mapper

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

def validate_policy_schema(policy_schema, user_policy, user):
    validate_status = True
    validationErrors = []
    v = Draft7Validator(policy_schema)
    for error in v.iter_errors(user_policy):
        validationErrors.append(error)

    if len(validationErrors) > 0:
        print("Failed to validate schema", user, "with error", validationErrors)
        validate_status = False

    return validate_status

def validate_mapper_schema(mapper_schema, user_mapper):
    validate_status = True
    validationErrors = []

    for account in user_mapper:
        if user_mapper[account][Mapper.CUSTOM.value] is True:
            v = Draft7Validator(rwro_account_schema)
        else:
            v = Draft7Validator(default_account_schema)
        for error in v.iter_errors(user_mapper[account][Mapper.ACCOUNTINFO.value]):
            validationErrors.append(error)
    v = Draft7Validator(mapper_schema)
    for error in v.iter_errors(user_mapper):
        validationErrors.append(error)

    if len(validationErrors) > 0:
        print("Failed to validate mapper with error", validationErrors)
        validate_status = False

    return validate_status

def validate_user_schema(user_schema, user_data):
    validate_status = True
    validationErrors = []
    v = Draft7Validator(user_schema)
    for error in v.iter_errors(user_data):
        validationErrors.append(error)

    if len(validationErrors) > 0:
        print("Failed to validate users with error", validationErrors)
        validate_status = False

    return validate_status

policy_schema = {
    "type": "object",
    "properties": {
        "Version": {
            "type": "string"
        },
        "Statement": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "Sid": { "type": "string" },
                    "Effect": { 
                        "type": "string",
                        "enum": ["Allow", "Deny"]
                    },
                    "Action": {
                        "type": ["array", "string"],
                        "items": {
                            "type": "string"
                        },
                        "minItems": 1,
                    },
                    "Resource": {
                        "type": ["array", "string"],
                        "minItems": 1
                    },
                    "Condition": { 
                        "type": "object",
                        "properties": {
                            "StringEqualsIgnoreCase": {
                                "type": "object",
                                "properties": {
                                    "aws:userid": {
                                        "type": ["array", "string"],
                                        "minItems": 1,
                                    }
                                },
                                "required": ["aws:userid"]
                            },
                        },
                        "patternProperties": {
                            ".*": {
                                "type": "object",
                                "patternProperties": {
                                    ".*":  {
                                        "patternProperties": {
                                            ".*": {"type": ["string", "array"]}
                                        }
                                    }
                                }
                            }
                        },
                        "required": ["StringEqualsIgnoreCase"]
                    }
                },
                "required": ["Effect", "Action", "Resource", "Condition"]
            }
        },
    },
    "required": ["Version", "Statement"],
}

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
    }
}

user_schema = {
    "type": "object",
    "properties": {
        "username": {"type": "string"},
        "userid": {"type": "string"},
        "arn": {"type": "string"},
        "AccessKey": {
            "type": "object",
            "properties": {
                "AccessKeyId": {"type": "string"},
                "SecretAccessKey": {"type": "string"},
            },
            "required": ["AccessKeyId", "SecretAccessKey"]
        },
        "slack-token": {"type": "string"},
    },
    "required": ["username", "userid", "arn", "AccessKey"]
}