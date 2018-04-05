#!/usr/bin/python
"""
Copyright 2018 Amazon.com, Inc. or its affiliates.
All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License").
You may not use this file except in compliance with the License.
A copy of the License is located at

   http://aws.amazon.com/apache2.0/

or in the "license" file accompanying this file.
This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.

This script orchestrates the enablement and centralization of GuardDuty across an enterprise of AWS accounts.
It takes in a list of AWS Account Numbers, iterates through each account and region to enable GuardDuty.
It creates each account as a Member in the GuardDuty Master account.
It invites and accepts the invite for each Member account.
"""

import boto3
import sys
import time
from collections import OrderedDict

# Global Variables
# :global aws_account_dict: Dictionary of AWS Accounts to enable GuardDuty in format AWS_Account_Number:Email_Address
# :global master_aws_account_number: GuardDuty Master Account, must be first in aws_account_list
# :global cloudformation_exec_role: Role to assume in accounts listed in aws_acount_list
# :global gd_invite_message: Message sent to Member accounts when invited to join GuardDuty Master
aws_account_dict = OrderedDict()

aws_account_dict['111111111111'] = 'me@example.com'
aws_account_dict['222222222222'] = 'you@example.com'
aws_account_dict['333333333333'] = 'someoneelse@example.com'

master_aws_account_number = '111111111111'
cloudformation_exec_role = 'AWSCloudFormationStackSetExecutionRole'
gd_invite_message = 'Account {account} invites you to join GuardDuty.'.format(account=master_aws_account_number)


def main():
    """
    Main function that orchestrates the other components
    :return: nothing
    """

    # Counter used to track metrics and determine if the master account is the first account
    account_counter = 0

    for account_str in aws_account_dict.keys():

        if account_counter == 0:
            if account_str != master_aws_account_number:
                # The Master GuardDuty Account was not the first account in the list
                sys.exit(
                    'The Master GuardDuty Account must be the first account in aws_account_dict.  '
                    'Please correct and retry.')

            master_detector_id_dict = master_guardduty_handler()
        else:
            monitored_guardduty_handler(account_str, master_detector_id_dict)

        # Increment the counter so we don't hit the master account loop again
        account_counter += 1


def accept_invitation(client, invitation_id, master_detector_id):
    """
    From the Member account, accepts the Invitation from the Master GuardDuty Account.
    :param client: GuardDuty Boto3 client
    :param invitation_id: Invitation Id from the Master GuardDuty Account to the Member
    :param master_detector_id: DetectorId for the Master GuardDuty Account in the specific AWS Region
    :return: Nothing
    """
    client.accept_invitation(
        DetectorId=master_detector_id,
        InvitationId=invitation_id,
        MasterId=master_aws_account_number
    )


def add_member(account, aws_region, master_detector_id):
    """
    Adds a Member DetectorId to the GuardDuty master account in the specified AWS Region
    :param account: Member AWS Account
    :param aws_region: AWS Region
    :param master_detector_id: DetectorId of the GuardDuty Master in the AWS Region
    :return: nothing
    """
    gd_client = assume_role(master_aws_account_number, cloudformation_exec_role, aws_region)

    gd_client.create_members(
        AccountDetails=[
            {
                'AccountId': account,
                'Email': aws_account_dict[account]
            }
        ],
        DetectorId=master_detector_id
    )

    print('Added Account {monitored} to member list in GuardDuty master account {master} for region {region}'.format(
        monitored=account, master=master_aws_account_number, region=aws_region))


def assume_role(aws_account_number, role_name, aws_region):
    """
    Assumes the provided role in each account and returns a GuardDuty client
    :param aws_account_number: AWS Account Number
    :param role_name: Role to assume in target account
    :param aws_region: AWS Region for the Client call, not required for IAM calls
    :return: GuardDuty client in the specified AWS Account and Region
    """

    # Beginning the assume role process for account
    sts_client = boto3.client('sts')
    response = sts_client.assume_role(
        RoleArn='arn:aws:iam::' + aws_account_number + ':role/' + role_name,
        RoleSessionName='EnableGuardDuty'
    )
    # Storing STS credentials
    session = boto3.Session(
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken'],
        region_name=aws_region
    )

    print("Assumed session for " + aws_account_number + " in region " + aws_region + ".")

    client = session.client('guardduty')

    return client


def create_detector(client):
    """
    Creates a GuardDuty Detector
    :param client: GuardDuty Boto3 client
    :return: DetectorId
    """
    response = client.create_detector(Enable=True)

    detector_id = response['DetectorId']

    return detector_id


def create_members(client, master_detector_id):
    """
    Creates a Member list for the master AWS Account that includes all Member accounts in the AWS Region
    :param client: GuardDuty client
    :param master_detector_id: DetectorId of the GuardDuty Master in the AWS Region
    :return: Nothing
    """
    for account in aws_account_dict.keys():
        # Don't invite yourself, so skip the master account
        if account != master_aws_account_number:
            client.create_members(
                AccountDetails=[
                    {
                        'AccountId': account,
                        'Email': aws_account_dict['account']
                    }
                ],
                DetectorId=master_detector_id
            )

            print('Added Account {monitored} to member list in GuardDuty in Account {master}'.format(
                monitored=account, master=master_aws_account_number))


def get_invitation_id(client, account):
    """
    Retrieves the InvitationId for a specifified Member from the GuardDuty Master in the AWS Region
    :param client:
    :param account:
    :return: Dictionary containg AWS_Account_Number: InvitationId
    """
    response = client.list_invitations()

    invitation_dict = dict()
    for invitation in response['Invitations']:
        invitation_dict.update({account: invitation['InvitationId']})

    return invitation_dict


def get_region_list():
    """
    Returns a list of valid AWS regions
    :return: list of AWS regions
    """
    ec2_client = boto3.client('ec2')

    # Retrieves all regions that work with EC2
    response = ec2_client.describe_regions()

    region_list = list()

    for region in response['Regions']:
        region_list.append(region['RegionName'])

    return region_list


def get_master_members(aws_region, detector_id):
    """
    Returns a list of current members of the GuardDuty master account
    :param aws_region: AWS Region of the GuardDuty master account
    :param detector_id: DetectorId of the GuardDuty master account in the AWS Region
    :return: dict of AwsAccountId:RelationshipStatus
    """

    member_dict = dict()

    gd_client = assume_role(master_aws_account_number, cloudformation_exec_role, aws_region)

    # Need to paginate and iterate over results
    paginator = gd_client.get_paginator('list_members')
    operation_parameters = {
        'DetectorId': detector_id,
        'OnlyAssociated': 'false'
    }
    page_iterator = paginator.paginate(**operation_parameters)

    for page in page_iterator:
        if page['Members']:
            for member in page['Members']:
                member_dict.update({member['AccountId']: member['RelationshipStatus']})

    return member_dict


def invite_members(aws_region, account, master_detector_id):
    """
    Invites monitored AWS Accounts to the GuardDuty master account in the AWS Region
    :param aws_region: AWS Region
    :param account: AWS Account to be monitored
    :param master_detector_id: DetectorId of the GuardDuty master account in the AWS Region
    :return: nothing
    """

    gd_client = assume_role(master_aws_account_number, cloudformation_exec_role, aws_region)

    gd_client.invite_members(
        AccountIds=[
            account
        ],
        DetectorId=master_detector_id,
        Message=gd_invite_message
    )

    print('Invited Account {monitored} to GuardDuty master account {master} in region {region}'.format(
        monitored=account, master=master_aws_account_number, region=aws_region))


def list_detectors(client, aws_region):
    """
    Lists the detectors in a given Account/Region
    Used to detect if a detector exists already
    :param client: GuardDuty client
    :param aws_region: AWS Region
    :return: Dictionary of AWS_Region: DetectorId
    """

    detector_dict = client.list_detectors()

    if detector_dict['DetectorIds']:
        for detector in detector_dict['DetectorIds']:
            detector_dict.update({aws_region: detector})
    else:
        detector_dict.update({aws_region: ''})

    return detector_dict


def master_guardduty_handler():
    """
    Handles logic for creating Detectors in the GuardDuty master account
    :return: dictionary containing AwsRegion: DetectorId for each AWS Region
    """

    master_detector_id_dict = dict()

    aws_regions_list = get_region_list()

    for aws_region in aws_regions_list:

        gd_client = assume_role(master_aws_account_number, cloudformation_exec_role, aws_region)
        # get detectors for this region
        detector_dict = list_detectors(gd_client, aws_region)

        if detector_dict[aws_region]:
            # a detector exists
            print('Found existing detector {detector} in {region} for {account}'.format(
                detector=detector_dict[aws_region], region=aws_region, account=master_aws_account_number
            ))
            master_detector_id_dict.update({aws_region: detector_dict[aws_region]})
        else:
            # create a detector
            detector_str = create_detector(gd_client)
            print('Created detector {detector} in {region} for {account}'.format(
                detector=detector_str, region=aws_region, account=master_aws_account_number
            ))
            master_detector_id_dict.update({aws_region: detector_str})

    return master_detector_id_dict


def monitored_guardduty_handler(account, master_detector_id_dict):
    """
    Handles logic for creating Detectors in Member accounts
    Adds Member accounts as Members in the GuardDuty Master Account
    Invites Member accounts
    Accepts Invitation from GuardDuty Master Account
    :param account: Member account
    :param master_detector_id_dict: DetectorId for the GuardDuty Master Account in the specified AWS Region
    :return: Nothing
    """

    aws_regions_list = get_region_list()

    for aws_region in aws_regions_list:
        print('Beginning {account} in {region}'.format(account=account, region=aws_region))
        gd_client = assume_role(account, cloudformation_exec_role, aws_region)
        # get detectors for this region
        detector_dict = list_detectors(gd_client, aws_region)
        detector_id = detector_dict[aws_region]

        # If detector does not exist, create it
        if detector_id:
            # a detector exists
            print('Found existing detector {detector} in {region} for {account}'.format(
                detector=detector_id, region=aws_region, account=account
            ))
        else:
            # create a detector
            detector_str = create_detector(gd_client)
            print('Created detector {detector} in {region} for {account}'.format(
                detector=detector_str, region=aws_region, account=account
            ))
            detector_id = detector_str

        master_detector_id = master_detector_id_dict[aws_region]
        member_dict = get_master_members(aws_region, master_detector_id)
        # If detector is not a member of the GuardDuty master account, add it
        if account not in member_dict:
            add_member(account, aws_region, master_detector_id)
            # not sure this is the best logic
            # repopulating member_dict now that we added the account as a member otherwise logic below is blown
            # waiting because it takes some time before the member shows up in the list
            while account not in member_dict:
                time.sleep(5)
                member_dict = get_master_members(aws_region, master_detector_id)
        else:
            print('Account {monitored} is already a member of {master} in region {region}'.format(
                monitored=account, master=master_aws_account_number, region=aws_region
            ))

        # Multiple logic decisions based on status
        # this looks odd because I used a key:value pair of AccountId:RelationshipStatus
        if member_dict[account] == 'Enabled':
            # Member is enabled and already being monitored
            print('Account {account} is already enabled'.format(account=account))
        else:
            while member_dict[account] != 'Enabled':
                if member_dict[account] == 'Created':
                    # Member has been created in the GuardDuty master account but not invited yet
                    invite_members(aws_region, account, master_detector_id)

                if member_dict[account] == 'Invited':
                    # member has been invited so accept the invite
                    invitation_dict = get_invitation_id(gd_client, account)
                    invitation_id = invitation_dict[account]
                    accept_invitation(gd_client, invitation_id, detector_id)

                # Refresh the member dictionary
                member_dict = get_master_members(aws_region, master_detector_id)
                print('Finished {account} in {region}'.format(account=account, region=aws_region))


if __name__ == '__main__':
    main()
