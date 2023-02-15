"""
This module contains SlackBot class
"""

import json
import time

import requests
from dotenv import load_dotenv

from slackbot_enum import SLACKBOTENUM, CHANGESTYPE, CHANGEVARIABLE

load_dotenv()


class SlackBot:
  """
  This class is used to send message to Slack channel
  """

  def __init__(self, secret):
    self.token = secret
    self.channel = "#alerts-permission"
    self.footer_icon = (
      "https://cncf-branding.netlify.app/img/"
      "projects/argo/stacked/color/argo-stacked-color.png"
    )
    self.title_link = (
      "https://example.com/"
      "applications/aws-iam-provisioner.development.main?resource="
    )
    self.time = time.time()

  def message_creator(self, current_status, change_type):
    error_text_message = "Policy {s} failed to excute in {t}"
    warn_text_message = "Policy {s} skipped to excute in {t}"
    success_text_message = "Policy {s} successfully excuted in {t}"
    default_name = "Policy"
    if change_type == CHANGESTYPE.VALIDATION.value:
        default_name = "AWS IAM Provisioner"
        error_text_message = CHANGESTYPE.VALIDATION.value.capitalize() + " for {s} failed"
    message_criteria = {
      SLACKBOTENUM.ERROR.value: {
        "title": "ERROR: " + default_name + " " + CHANGEVARIABLE(change_type).name +  " failed for: {s}",
        "text": error_text_message + "\n\nDetails:\n{m}",
      },
      SLACKBOTENUM.WARNING.value: {
        "title": "WARNING: " + default_name + " " + CHANGEVARIABLE(change_type).name + " skipped for: {s}",
        "text": warn_text_message + "\n\nDetails:\n{m}",
      },
      SLACKBOTENUM.SUCCESS.value: {
        "title": "SUCCESS: " + default_name + " " +  CHANGEVARIABLE(change_type).name + " created for: {s}",
        "text": success_text_message + "\n\nDetails:\n{m}",
      },
    }

    return message_criteria[current_status]


  def get_fail_message(self, environment, policy_name, message, change_type):
    fail = [
      {
        "color": "#DC143C",
        "title": self.message_creator(SLACKBOTENUM.ERROR.value, change_type)[
          "title"
        ].format(t=environment, s=policy_name, m=message),
        "title_link": self.title_link,
        "text": self.message_creator(SLACKBOTENUM.ERROR.value, change_type)[
          "text"
        ].format(t=environment, s=policy_name, m=message),
        "footer": "AWS IAM Provisioner",
        "footer_icon": self.footer_icon,
        "ts": self.time,
      }
    ]
    return fail

  def get_warn_message(self, environment, policy_name, message, change_type):
    warn = [
      {
        "color": "#F4BB44",
        "title": self.message_creator(SLACKBOTENUM.WARNING.value, change_type)[
          "title"
        ].format(t=environment, s=policy_name, m=message),
        "title_link": self.title_link,
        "text": self.message_creator(SLACKBOTENUM.WARNING.value, change_type)[
          "text"
        ].format(t=environment, s=policy_name, m=message),
        "footer": "Pod Autoscaler",
        "footer_icon": self.footer_icon,
        "ts": self.time,
      }
    ]
    return warn

  def get_success_message(self, environment, policy_name, message, change_type):
    success = [
      {
        "color": "#2eb886",
        "title": self.message_creator(SLACKBOTENUM.SUCCESS.value, change_type)[
          "title"
        ].format(t=environment, s=policy_name, m=message),
        "title_link": self.title_link,
        "text": self.message_creator(SLACKBOTENUM.SUCCESS.value, change_type)[
          "text"
        ].format(t=environment, s=policy_name, m=message),
        "footer": "Pod Autoscaler",
        "footer_icon": self.footer_icon,
        "ts": self.time,
      }
    ]
    return success

  def post_message_to_slack(self, attachments):
    return requests.post(
      "https://slack.com/api/chat.postMessage",
      {
        "token": self.token,
        "channel": self.channel,
        "text": None,
        "attachments": json.dumps(attachments),
      },
      timeout=5,
    ).json()

  def post_warn_message_to_slack(self, environment, policy_name, message, change_type):
    attachments = self.get_warn_message(environment, policy_name, message, change_type)
    return self.post_message_to_slack(attachments)

  def post_fail_message_to_slack(self, environment, policy_name, message, change_type):
    attachments = self.get_fail_message(environment, policy_name, message, change_type)
    return self.post_message_to_slack(attachments)

  def post_success_message_to_slack(self, environment, policy_name, message, change_type):
    attachments = self.get_success_message(environment, policy_name, message, change_type)
    return self.post_message_to_slack(attachments)
