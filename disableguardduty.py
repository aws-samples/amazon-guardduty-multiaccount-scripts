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

This script orchestrates the disabling of GuardDuty across an enterprise of AWS accounts.
It takes in a list of AWS Account Numbers, iterates through each account and region to disable GuardDuty.
It removes each account as a Member in the GuardDuty Master account.
"""

import boto3
from collections import OrderedDict

# Global Variables
#:global aws_account_list: List of AWS Accounts to disable GuardDuty
# GuardDuty Master Account, must be first in aws_account_list
#:global cloudformation_exec_role: Role to assume in accounts listed in aws_acount_list
aws_account_dict = OrderedDict()

aws_account_dict['111111111111'] = 'me@example.com'
aws_account_dict['222222222222'] = 'you@example.com'
aws_account_dict['333333333333'] = 'someoneelse@example.com'

master_aws_account_number = '111111111111'
cloudformation_exec_role = 'AWSCloudFormationStackSetExecutionRole'


def main():
    """
    Main function that orchestrates the other components
    :return: nothing
    """

    account_counter = 0

    for account_str, account_email in aws_account_dict.items():
        aws_region_list = get_region_list()

        for aws_region in aws_region_list:
            gd_client = assume_role(account_str, cloudformation_exec_role, aws_region)

            detector_dict = list_detectors(gd_client, aws_region)

            detector_id = detector_dict[aws_region]

            if detector_id != '':
                print('GuardDuty is active in {region}'.format(region=aws_region))

            if account_counter == 0 and detector_id != '':
                if account_str != master_aws_account_number:
                    # The Master GuardDuty Account was not the first account in the list
                    sys.exit(
                        'The Master GuardDuty Account must be the first account in aws_account_dict.  '
                        'Please correct and retry.')
                member_dict = list_members(gd_client, detector_id)
                if member_dict:
                    print('There are members in {region}'.format(region=aws_region))
                    member_account_ids = [member_account_id for member_account_id, member_relationship_status in member_dict.items()
                    if member_relationship_status == 'Enabled' or member_relationship_status == 'Disabled']

                    disassociate_members(gd_client, detector_id, member_account_ids, account_str, aws_region)

                    delete_members(gd_client, detector_id, member_dict.keys(), account_str, aws_region)

            if detector_id != '':
                delete_detector(gd_client, detector_id)
                print('Deleted {detector} for {account} in {region}.'.format(detector=detector_id,account=account_str,region=aws_region))
            else:
                print('No detector found for {account} in {region}'.format(account=account_str,region=aws_region))

        account_counter += 1


def delete_detector(client, detector_id):
    response = client.delete_detector(
        DetectorId=detector_id
    )


def delete_members(client, detector_id, account_ids, master_account, aws_region):
    response = client.delete_members(
        DetectorId=detector_id,
        AccountIds=account_ids
    )

    print('Deleted members for {account} in {region}'.format(account=master_account, region=aws_region))

def disassociate_members(client, detector_id, account_ids, master_account, aws_region):
    response = client.disassociate_members(
        DetectorId=detector_id,
        AccountIds=account_ids
    )

    print('Disassociated members for {account} in {region}'.format(account=master_account, region=aws_region))

def list_detectors(client, aws_region):
    """
    Lists the detectors in a given Account/Region
    Used to detect if a detector exists already
    :param client: GuardDuty client
    :return: list of Detectors
    """

    detector_dict = client.list_detectors()

    if detector_dict['DetectorIds']:
        for detector in detector_dict['DetectorIds']:
            detector_dict.update({aws_region:detector})
    else:
        detector_dict.update({aws_region: ''})

    return detector_dict


def list_members(client, detector_id):

    member_dict = dict()

    response = client.list_members(
        DetectorId=detector_id,
        OnlyAssociated='false'
    )

    for member in response['Members']:
        member_dict.update({member['AccountId']:member['RelationshipStatus']})

    return member_dict


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
        RoleSessionName='DisableGuardDuty'
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


def get_region_list():
    """
    Returns a list of valid AWS regions GuardDuty is launched in.
    :return: list of AWS regions
    """
    region_list = list(['ap-south-1', 'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2',
        'ap-northeast-1', 'ca-central-1', 'eu-central-1', 'eu-west-1', 'eu-west-2',
        'eu-west-3', 'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'sa-east-1'])

    return region_list


def troubleshoot_this(thing):
    """
    Troubleshooting function
    :param thing: That naughty thing in your code that isn't working correctly
    :return: the Type and Value of the naughty thing
    """
    thing_type_str = str(type(thing))
    print('The thing is a type of: {thing_type}'.format(thing_type=thing_type_str))
    print('The value of thing is: ')
    print(thing)


if __name__ == '__main__':
    main()
