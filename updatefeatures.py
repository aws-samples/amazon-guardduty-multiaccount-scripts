#!/usr/bin/env python
"""
Copyright 2022 Amazon.com, Inc. or its affiliates.
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
import argparse
import re

from collections import OrderedDict
from botocore.exceptions import ClientError


def assume_role(aws_account_number, role_name):
    """
    Assumes the provided role in each account and returns a GuardDuty client
    :param aws_account_number: AWS Account Number
    :param role_name: Role to assume in target account
    :param aws_region: AWS Region for the Client call, not required for IAM calls
    :return: GuardDuty client in the specified AWS Account and Region
    """

    # Beginning the assume role process for account
    sts_client = boto3.client('sts')

    # Get the current partition
    partition = sts_client.get_caller_identity()['Arn'].split(":")[1]

    response = sts_client.assume_role(
        RoleArn='arn:{}:iam::{}:role/{}'.format(
            partition,
            aws_account_number,
            role_name
        ),
        RoleSessionName='EnableGuardDuty'
    )

    # Storing STS credentials
    session = boto3.Session(
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken']
    )

    print("Assumed session for {}.".format(
        aws_account_number
    ))

    return session


def get_master_members(master_session, aws_region, detector_id):
    """
    Returns a list of current members of the GuardDuty master account
    :param aws_region: AWS Region of the GuardDuty master account
    :param detector_id: DetectorId of the GuardDuty master account in the AWS Region
    :return: dict of AwsAccountId:RelationshipStatus
    """

    member_dict = dict()

    gd_client = master_session.client('guardduty', region_name=aws_region)

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

def str_to_bool(value):
    if isinstance(value, bool):
        return value
    if value.lower() in {'false', 'f', '0', 'no', 'n'}:
        return False
    elif value.lower() in {'true', 't', '1', 'yes', 'y'}:
        return True
    raise ValueError(f'{value} is not a valid boolean value')

if __name__ == '__main__':

    # Setup command line arguments
    parser = argparse.ArgumentParser(description='Link AWS Accounts to central GuardDuty Account')
    parser.add_argument('--master_account', type=str, required=True, help="AccountId for Central AWS Account")
    parser.add_argument('input_file', type=argparse.FileType('r'), help='Path to CSV file containing the list of account IDs and Email addresses')
    parser.add_argument('--assume_role', type=str, required=True, help="Role Name to assume in each account")
    parser.add_argument('--enabled_regions', type=str, help="comma separated list of regions to enable GuardDuty. If not specified, all available regions are worked on")
    parser.add_argument('--enable_malware', help="Enables GuardDuty Malware Protection", type=str_to_bool, nargs='?', const=True, default=False)
    parser.add_argument('--enable_eks', help="Enables GuardDuty for EKS", type=str_to_bool, nargs='?', const=True, default=False)
    parser.add_argument('--enable_s3', help="Enables GuardDuty S3 Protection", type=str_to_bool, nargs='?', const=True, default=False)
    parser.add_argument('--disable_malware', help="Disable GuardDuty Malware Protection", type=str_to_bool, nargs='?', const=True, default=False)
    parser.add_argument('--disable_eks', help="Disable GuardDuty for EKS", type=str_to_bool, nargs='?', const=True, default=False)
    parser.add_argument('--disable_s3', help="Disable GuardDuty S3 Protection", type=str_to_bool, nargs='?', const=True, default=False)
    parser.add_argument('--debug', help="Turns on more verbose logging", action='store_true')
    args = parser.parse_args()

    data_sources = {}

    if args.enable_s3:
        data_sources['S3Logs'] = {'Enable': True}
    elif args.disable_s3:
        data_sources['S3Logs'] = {'Enable': False}
    if args.enable_malware:
        data_sources["MalwareProtection"] = {"ScanEc2InstanceWithFindings":{"EbsVolumes":True}}
    elif args.disable_malware:
        data_sources["MalwareProtection"] = {"ScanEc2InstanceWithFindings":{"EbsVolumes":False}}
    if args.enable_eks:
        data_sources["Kubernetes"] = {"AuditLogs":{"Enable":True}}
    elif args.disable_eks:
        data_sources["Kubernetes"] = {"AuditLogs":{"Enable":False}}

    if not data_sources.keys():
        raise ValueError("At least one feature must be enabled/disabled")

    # Validate master accountId
    if not re.match(r'[0-9]{12}', args.master_account):
        raise ValueError("Master AccountId is not valid")

    # Generate dict with account & email information
    aws_account_dict = OrderedDict()

    for acct in args.input_file.readlines():
        split_line = acct.rstrip().split(",")
        if len(split_line) < 2:
            print("Unable to process line: {}".format(acct))
            continue

        if not re.match(r'[0-9]{12}', str(split_line[0])):
            print("Invalid account number {}, skipping".format(split_line[0]))
            continue

        aws_account_dict[split_line[0]] = split_line[1]

    # Check length of accounts to be processed
    if len(aws_account_dict.keys()) > 1000:
        raise Exception("Only 1000 accounts can be linked to a single master account")

    # Getting GuardDuty regions
    session = boto3.session.Session()

    guardduty_regions = []
    if args.enabled_regions:
        guardduty_regions = [str(item) for item in args.enabled_regions.split(',')]
        print("Enabling members in these regions: {}".format(guardduty_regions))
    else:
        guardduty_regions = session.get_available_regions('guardduty')
        print("Enabling members in all available GuardDuty regions {}".format(guardduty_regions))

    # Setting the invitationmessage
    gd_invite_message = 'Account {account} invites you to join GuardDuty.'.format(account=args.master_account)

    master_detector_id_dict = dict()
    failed_master_regions = []
    # Processing Master account
    master_session = assume_role(args.master_account, args.assume_role)

    for aws_region in guardduty_regions:
        try:
            gd_client = master_session.client('guardduty', region_name=aws_region)

            detector_dict = list_detectors(gd_client, aws_region)
            detector_id = detector_dict[aws_region]

            if not detector_id:
                print("Region does not have GuardDuty enabled, cannot update features")
                failed_master_regions.append(aws_region)
                continue

            if args.enable_malware:
                print("Creating Service Linked Role for Malware Protection")
                try:
                    master_session.client('iam').create_service_linked_role(AWSServiceName="malware-protection.guardduty.amazonaws.com")
                except ClientError as err:
                    if 'has been taken in this account' in err.response.get('Error').get('Message'):
                        print("Service Linked Role has already been created for master account")
                    else:
                        print("Could not create Service Linked Role for master account: {}".format(err))
                        failed_master_regions.append(aws_region)
                        continue

            # a detector exists
            print('Found existing detector {detector} in {region} for {account}'.format(
                detector=detector_dict[aws_region],
                region=aws_region,
                account=args.master_account
            ))

            master_detector_id_dict.update({aws_region: detector_dict[aws_region]})
        except ClientError as err:
            if err.response['ResponseMetadata']['HTTPStatusCode'] == 403:
                print("Failed to list detectors in Master account for region: {} due to an authentication error.  Either your credentials are not correctly configured or the region is an OptIn region that is not enabled on the master account.  Skipping {} and attempting to continue".format(aws_region, aws_region))
                failed_master_regions.append(aws_region)

    for failed_region in failed_master_regions:
        guardduty_regions.remove(failed_region)

    # Processing accounts to be linked
    failed_accounts = []
    for account in aws_account_dict.keys():
        try:
            session = assume_role(account, args.assume_role)

            for aws_region in guardduty_regions:
                try:
                    print('Beginning {account} in {region}'.format(
                        account=account,
                        region=aws_region
                    ))

                    gd_client = session.client('guardduty', region_name=aws_region)

                    # get detectors for this region
                    detector_dict = list_detectors(gd_client, aws_region)
                    detector_id = detector_dict[aws_region]

                    if not detector_id:
                        failed_accounts.append({
                            account: "Guardduty must be enabled for account"
                        })
                        continue

                    print('Found existing detector {detector} in {region} for {account}'.format(
                        detector=detector_id,
                        region=aws_region,
                        account=account
                    ))

                    master_detector_id = master_detector_id_dict[aws_region]
                    member_dict = get_master_members(master_session, aws_region, master_detector_id)
                    master_client = master_session.client('guardduty', region_name=aws_region)

                    if account not in member_dict:
                        failed_accounts.append({
                            account: "Account is not a member of under account {manager}".format(manager=args.master_account)
                        })
                        continue

                    if args.enable_malware:
                        print("Creating Service Linked Role for Malware Protection for {}".format(account))
                        try:
                            session.client('iam').create_service_linked_role(AWSServiceName="malware-protection.guardduty.amazonaws.com")
                        except ClientError as err:
                            if 'has been taken in this account' in err.response.get('Error').get('Message'):
                                print("Service Linked Role has already been created for this account")
                            else:
                                failed_accounts.append({
                                    account: "Failed to create Service Linked Role: {}".format(err),
                                })
                                continue
                    try:
                        update = master_client.update_member_detectors(
                                DetectorId=master_detector_id,
                                AccountIds=[account],
                                DataSources=data_sources
                        )
                        print('Updated features for {monitored} with {detector_id} from GuardDuty master account {master} in region {region} to {data_sources}'.format(
                            monitored=account,
                            master=args.master_account,
                            region=aws_region,
                            data_sources=data_sources,
                            detector_id=detector_id,
                        ))
                        if args.debug:
                            print('Update features response: {resp}'.format(resp=update))

                        unprocessed = update.get('UnprocessedAccounts')
                        if unprocessed:
                            failed_accounts.append({account: unprocessed[0]['Result']})
                            continue

                    except ClientError as err:
                        if err.response['ResponseMetadata']['HTTPStatusCode'] == 403:
                            e = "Lacking permissions to UpdateMemberDetectors"
                        else:
                            e = repr(err)
                        failed_accounts.append({
                            account: e
                        })

                    print('Finished {account} in {region}'.format(account=account, region=aws_region))
                except ClientError as err:
                    if err.response['ResponseMetadata']['HTTPStatusCode'] == 403:
                        print("Failed to list detectors in Target account for region: {} due to an authentication error.  Either your credentials are not correctly configured or the region is an OptIn region that is not enabled on the target account.  Skipping {} and attempting to continue".format(aws_region, aws_region))

        except ClientError as e:
            print("Error Processing Account {}".format(account))
            failed_accounts.append({
                account: repr(e)
            })

    if len(failed_accounts) > 0:
        print("---------------------------------------------------------------")
        print("Failed Accounts")
        print("---------------------------------------------------------------")
        for account in failed_accounts:
            print("{}: \n\t{}".format(
                list(account.keys())[0],
                account[list(account.keys())[0]]
            ))
            print("---------------------------------------------------------------")

