"""This is the main enum for AWS IAM Provisioner

Consist of all static variable in the AWS IAM Provisioner
"""
from enum import Enum

class RWRO(Enum):
  ReadOnly = "ro"
  ReadWrite = "rw"

class PermissionSet(Enum):
  Version = "Version"
  Statement = "Statement"

class Policies(Enum):
  Sid = "Sid"
  Effect = "Effect"
  Action = "Action"
  Resource = "Resource"
  Condition = "Condition"

class ConditionMust(Enum):
  StringEqualsIgnoreCase = "StringEqualsIgnoreCase"

class ConditionUserID(Enum):
  UserID = "aws:userid"

class Mapper(Enum):
  AccountID = "AccountID"
  ACCOUNTINFO = "account_info"
  CUSTOM = "custom"
  SAML = "SAML"
  Role = "Role"
  RoleArn = "RoleArn"
  RoleID = "RoleID"