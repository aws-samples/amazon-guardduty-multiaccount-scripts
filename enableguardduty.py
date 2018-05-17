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

if __name__ == '__main__':
    
    # Setup command line arguments
    parser = argparse.ArgumentParser(description='Link AWS Accounts to central GuardDuty Account')
    parser.add_argument('--master_account', type=int, help="AccountId for Central AWS Account")
    parser.add_argument('input_file', type=argparse.FileType('r'), help='Path to CSV file in the format of accountId, email, ...')
    parser.add_argument('--assume_role', type=str, default='AWSCloudFormationStackSetExecutionRole', help="Role Name to assume in each account")
    args = parser.parse_args()
    
    # Validate master accountId
    if not re.match(r'[0-9]{12}',str(args.master_account)):
        raise ValueError("Master AccountId is not valid")
    
    # Generate dict with account & email information
    aws_account_dict = OrderedDict()
    
    for acct in args.input_file.readlines():
        split_line = acct.replace("\n",'').split(",")
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
    guardduty_regions = session.get_available_regions('guardduty')
    
    # Setting the invitationmessage
    gd_invite_message = 'Account {account} invites you to join GuardDuty.'.format(account=args.master_account)

    master_detector_id_dict = dict()

    # Processing Master account
    master_session = assume_role(args.master_account, args.assume_role)
    for aws_region in guardduty_regions:

        gd_client = master_session.client('guardduty', region_name=aws_region)
        
        detector_dict = list_detectors(gd_client, aws_region)

        if detector_dict[aws_region]:
            # a detector exists
            print('Found existing detector {detector} in {region} for {account}'.format(
                detector=detector_dict[aws_region],
                region=aws_region,
                account=args.master_account
            ))
            
            master_detector_id_dict.update({aws_region: detector_dict[aws_region]})
            
        else:
            
            # create a detector
            detector_str = gd_client.create_detector(Enable=True)['DetectorId']
            print('Created detector {detector} in {region} for {account}'.format(
                detector=detector_str,
                region=aws_region,
                account=args.master_account
            ))
            
            master_detector_id_dict.update({aws_region: detector_str})

    # Processing accounts to be linked
    failed_accounts = []
    for account in aws_account_dict.keys():
        try:
            session = assume_role(account, args.assume_role)
            
            for aws_region in guardduty_regions:
                print('Beginning {account} in {region}'.format(
                    account=account,
                    region=aws_region
                ))
                
                gd_client = session.client('guardduty', region_name=aws_region)
                
                # get detectors for this region
                detector_dict = list_detectors(gd_client, aws_region)
                detector_id = detector_dict[aws_region]
        
                # If detector does not exist, create it
                if detector_id:
                    # a detector exists
                    print('Found existing detector {detector} in {region} for {account}'.format(
                        detector=detector_id,
                        region=aws_region,
                        account=account
                    ))
                    
                else:
                    # create a detector
                    detector_str = gd_client.create_detector(Enable=True)['DetectorId']
                    print('Created detector {detector} in {region} for {account}'.format(
                        detector=detector_str,
                        region=aws_region,
                        account=account
                    ))
                    
                    detector_id = detector_str
        
                master_detector_id = master_detector_id_dict[aws_region]
                member_dict = get_master_members(master_session, aws_region, master_detector_id)
                
                # If detector is not a member of the GuardDuty master account, add it
                if account not in member_dict:
                    gd_client = master_session.client('guardduty', region_name=aws_region)
        
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
                        monitored=account,
                        master=args.master_account,
                        region=aws_region
                    ))
                                
                    start_time = int(time.time())
                    while account not in member_dict:
                        if (int(time.time()) - start_time) > 300:
                            print("Membership did not show up for account {}, skipping".format(account))
                            break
                        
                        time.sleep(5)
                        member_dict = get_master_members(master_session, aws_region, master_detector_id)
                        
                else:
                    print('Account {monitored} is already a member of {master} in region {region}'.format(
                        monitored=account,
                        master=args.master_account,
                        region=aws_region
                    ))
        
                if member_dict[account] == 'Enabled':
                    # Member is enabled and already being monitored
                    print('Account {account} is already enabled'.format(account=account))
                    
                else:
                    master_gd_client = master_session.client('guardduty', region_name=aws_region)
                    gd_client = session.client('guardduty', region_name=aws_region)
                    
                    while member_dict[account] != 'Enabled':
                        
                        
                        if member_dict[account] == 'Created':
                            # Member has been created in the GuardDuty master account but not invited yet
                            master_gd_client = master_session.client('guardduty', region_name=aws_region)
        
                            master_gd_client.invite_members(
                                AccountIds=[
                                    account
                                ],
                                DetectorId=master_detector_id,
                                Message=gd_invite_message
                            )
                        
                            print('Invited Account {monitored} to GuardDuty master account {master} in region {region}'.format(
                                monitored=account,
                                master=args.master_account,
                                region=aws_region
                            ))
        
                        if member_dict[account] == 'Invited':
                            # member has been invited so accept the invite
                            
                            response = gd_client.list_invitations()
        
                            invitation_dict = dict()
                            
                            invitation_id = None
                            for invitation in response['Invitations']:
                                invitation_id = invitation['InvitationId']
                            
                            if invitation_id is not None:
                                gd_client.accept_invitation(
                                    DetectorId=detector_id,
                                    InvitationId=invitation_id,
                                    MasterId=str(args.master_account)
                                )
                                print('Accepting Account {monitored} to GuardDuty master account {master} in region {region}'.format(
                                    monitored=account,
                                    master=args.master_account,
                                    region=aws_region
                                ))
    
                        # Refresh the member dictionary
                        member_dict = get_master_members(master_session, aws_region, master_detector_id)
                        
                    print('Finished {account} in {region}'.format(account=account, region=aws_region))
                    
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
                account.keys()[0],
                account[account.keys()[0]]
            ))
            print("---------------------------------------------------------------")