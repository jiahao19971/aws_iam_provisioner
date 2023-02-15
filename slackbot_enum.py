"""This is the main enum for Slackbot

Consist of all static variable in the Slackbot
"""
from enum import Enum


class CHANGESTYPE(Enum):
  UPDATE = "update"
  DELETE = "delete"
  CREATE = "create"
  VALIDATION = "validation"

class CHANGEVARIABLE(Enum):
  update = "update"
  deletion = "delete"
  creation = "create"
  validation = "validation"
  

class SLACKBOTENUM(Enum):
  ERROR = "error"
  WARNING = "warning"
  SUCCESS = "success"
