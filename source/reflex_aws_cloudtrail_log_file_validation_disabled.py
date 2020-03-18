""" Module for CloudTrailLogFileValidationDisabled """

import json
import os

import boto3
from reflex_core import AWSRule


class CloudTrailLogFileValidationDisabled(AWSRule):
    """ Rule to detect CloudTrail File Validation disabled. """
    def __init__(self, event):
        super().__init__(event)

    def extract_event_data(self, event):
        """ Extract required event data """
        self.trail_name = event["detail"]["responseElements"]["name"]
        self.log_validation_enabled = event["detail"]["responseElements"]["logFileValidationEnabled"]


    def resource_compliant(self):
        """
        Determine if the resource is compliant with your rule.

        Return True if it is compliant, and False if it is not.
        """
        return self.log_validation_enabled

    def get_remediation_message(self):
        """ Returns a message about the remediation action that occurred """
        return f"The CloudTrail trail {self.trail_name} has log validation disabled."


def lambda_handler(event, _):
    """ Handles the incoming event """
    rule = CloudTrailLogFileValidationDisabled(json.loads(event["Records"][0]["body"]))
    rule.run_compliance_rule()
