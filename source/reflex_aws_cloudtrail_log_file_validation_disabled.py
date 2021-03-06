""" Module for CloudTrailLogFileValidationDisabled """

import json
import os

import boto3
from reflex_core import AWSRule, subscription_confirmation


class CloudTrailLogFileValidationDisabled(AWSRule):
    """ Rule to detect CloudTrail File Validation disabled. """

    def __init__(self, event):
        super().__init__(event)

    def extract_event_data(self, event):
        """ Extract required event data """
        self.trail_name = event["detail"]["responseElements"]["name"]
        self.log_validation_enabled = event["detail"]["responseElements"][
            "logFileValidationEnabled"
        ]

    def resource_compliant(self):
        """
        Determine if the resource is compliant with your rule.

        Return True if it is compliant, and False if it is not.
        """
        return self.log_validation_enabled

    def remediate(self):
        """ Fix the non-compliant resource """
        self.turn_on_log_validation()

    def turn_on_log_validation(self):
        self.client.update_trail(Name=self.trail_name, EnableLogFileValidation=True)

    def get_remediation_message(self):
        """ Returns a message about the remediation action that occurred """
        message = f"The CloudTrail trail {self.trail_name} has log validation disabled."
        if self.should_remediate():
            message += " Log validation has been re-enabled."
        return message


def lambda_handler(event, _):
    """ Handles the incoming event """
    print(event)
    event_payload = json.loads(event["Records"][0]["body"])
    if subscription_confirmation.is_subscription_confirmation(event_payload):
        subscription_confirmation.confirm_subscription(event_payload)
        return
    rule = CloudTrailLogFileValidationDisabled(event_payload)
    rule.run_compliance_rule()
