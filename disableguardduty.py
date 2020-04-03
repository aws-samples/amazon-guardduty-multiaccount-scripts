#!/usr/bin/env python
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
import re
import argparse

from collections import OrderedDict
from botocore.exceptions import ClientError


cloudformation_exec_role = 'AWSCloudFormationStackSetExecutionRole'

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

if __name__ == '__main__':
    
    # Setup command line arguments
    parser = argparse.ArgumentParser(description='Link AWS Accounts to central GuardDuty Account')
    parser.add_argument('--master_account', type=int, required=True, help="AccountId for Central AWS Account")
    parser.add_argument('input_file', type=argparse.FileType('r'), help='Path to CSV file containing the list of account IDs and Email addresses')
    parser.add_argument('--assume_role', type=str, required=True, help="Role Name to assume in each account")
    parser.add_argument('--delete_master', action='store_true', default=False, help="Delete the master Gd Detector")
    parser.add_argument('--enabled_regions', type=str, help="comma separated list of regions to remove GuardDuty. If not specified, all available regions disabled")
    args = parser.parse_args()
    
    # Validate master accountId
    if not re.match(r'[0-9]{12}',str(args.master_account)):
        raise ValueError("Master AccountId is not valid")
    
    
    # Generate dict with account & email information
    aws_account_dict = OrderedDict()
    
    for acct in args.input_file.readlines():
        split_line = acct.rstrip().split(",")
        if len(split_line) < 2:
            print("Unable to process line: {}".format(acct))
            continue
            
        if not re.match(r'[0-9]{12}',str(split_line[0])):
            print("Invalid account number {}, skipping".format(split_line[0]))
            continue
            
        aws_account_dict[split_line[0]] = split_line[1]
    
    # Getting GuardDuty regions
    session = boto3.session.Session()
    guardduty_regions = []
    if args.enabled_regions:
        guardduty_regions = [str(item) for item in args.enabled_regions.split(',')]
        print("Disabling members in these regions: {}".format(guardduty_regions))
    else:
        guardduty_regions = session.get_available_regions('guardduty')
        print("Disabling members in all available GuardDuty regions {}".format(guardduty_regions))
    
    failed_master_regions = []
    master_session = assume_role(args.master_account, args.assume_role)
            
    for aws_region in guardduty_regions:
        try:
            gd_client = master_session.client('guardduty', region_name=aws_region)

            detector_dict = list_detectors(gd_client, aws_region)

            detector_id = detector_dict[aws_region]

            if detector_id != '':
                print('GuardDuty is active in {region}'.format(region=aws_region))

            if detector_id != '':
                member_dict = list_members(gd_client, detector_id)
            
                if member_dict:
                    print('There are members in {region}'.format(region=aws_region))
                    if args.delete_master:
                    
                        response = gd_client.disassociate_members(
                            AccountIds=list(member_dict.keys()),
                            DetectorId=detector_id
                        )
                    
                        response = gd_client.delete_members(
                            DetectorId=detector_id,
                            AccountIds=list(member_dict.keys())
                        )
                    
                    else:
                        response = gd_client.disassociate_members(
                            AccountIds=list(aws_account_dict.keys()),
                            DetectorId=detector_id
                        )
                    
                        response = gd_client.delete_members(
                            DetectorId=detector_id,
                            AccountIds=list(aws_account_dict.keys())
                        )
                
                    print('Deleting members for {account} in {region}'.format(
                        account=args.master_account,
                        region=aws_region
                    ))
    
                if args.delete_master:
                    response = gd_client.delete_detector(
                        DetectorId=detector_id
                    )
            else:
                print('No detector found for {account} in {region}'.format(
                    account=args.master_account,
                    region=aws_region
                ))
        except ClientError as err:
            if err.response['ResponseMetadata']['HTTPStatusCode'] == 403:
                print("Failed to list detectors in Master account for region: {} due to an authentication error.  Either your credentials are not correctly configured or the region is an OptIn region that is not enabled on the master account.  Skipping {} and attempting to continue".format(aws_region, aws_region))
                failed_master_regions.append(aws_region) 
                
    for failed_region in failed_master_regions:
        guardduty_regions.remove(failed_region)

    failed_accounts = []
    for account_str, account_email in aws_account_dict.items():
        try:
            session = assume_role(account_str, args.assume_role)
            
            for aws_region in guardduty_regions:
                gd_client = session.client('guardduty', region_name=aws_region)
    
                detector_dict = list_detectors(gd_client, aws_region)
    
                detector_id = detector_dict[aws_region]
    
                if detector_id != '':
                    print('GuardDuty is active in {region}'.format(region=aws_region))
    
                if detector_id != '':
                    response = gd_client.delete_detector(
                        DetectorId=detector_id
                    )
                    
                    print('Deleted {detector} for {account} in {region}.'.format(
                        detector=detector_id,
                        account=account_str,
                        region=aws_region
                    ))
                    
                else:
                    print('No detector found for {account} in {region}'.format(
                        account=account_str,
                        region=aws_region
                    ))
        except ClientError as e:
            print("Error Processing Account {}".format(account_str))
            failed_accounts.append({
                account_str: repr(e)
            })
    
    if len(failed_accounts) > 0:
        print("---------------------------------------------------------------")
        print("Failed Accounts")
        print("---------------------------------------------------------------")
        for account in failed_accounts:
            print("{}: \n\t{}".format(
                account.keys()[0],
                account[account.keys()[0]]
            ))
            print("---------------------------------------------------------------")
