# amazon-guardduty-multiaccount-scripts

This script automates the process of running the GuardDuty multi-account workflow across a group
of accounts that are in your control. It will enable GuardDuty, send invitations from the master account
and accept invitations in all member accounts. It relies on having a role that can be assumed in each
of these accounts such as the AWSCloudFormationStackSetExecutionRole from the StackSets service.

The result will be a master account that contains all security findings for all member accounts. Since
GuardDuty is regionally isolated, findings for each member account will roll up to the corresponding
region in the master account. For example, the us-east-1 region in your GuardDuty master account will
contain the security findings for all us-east-1 findings from all associated member accounts.

## Prerequisites

These scripts are dependent on having roles setup in each account that provide access to Amazon
GuardDuty. The scripts were modelled with the StackSets service in mind. That service already
has the prerequsite to have a AWSCloudFormationStackSetExecutionRole in each account. If you
are already using StackSets and have these setup, the scripts can leverage these existing roles.
If not, you can setup an AWSCloudFormationStackSetExecutionRole in
each account using Step 2 in these instructions:
[https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-prereqs.html#stacksets-prereqs-accountsetup Prerequisite]

## Step 1

Be sure you have a AWSCloudFormationStackSetExecutionRole present in all accounts that
will allow our script to interact with the GuardDuty service at a minimum. The simplest
way to do this is to run the following CloudFormation template in each account (master and member):
[https://s3.amazonaws.com/cloudformation-stackset-sample-templates-us-east-1/AWSCloudFormationStackSetExecutionRole.yml CloudFormation]

The script has one parameter which will be the account number of your master account.

## Step 2
Update the Global variables in the script to map to your accounts.  You will need to create a list
of the accounts and their associated email addresses.  You will specify the master account
and you can also customize the invite message that is sent if you'd like to. 

## Step 3
The simplest way to test these scripts is to launch a new Amazon Linux instance with a role that
has administrative permissions. You can then login to the instance and do the following:

<code>sudo yum install git python
sudo pip install boto3
aws configure (set the region to us-east-1 (or whatever default region you want))
git clone git@github.com:tomstickle/amazon-guardduty-multiaccount-scripts.git
cd amazon-guardduty-multiaccount-scripts
sudo chmod +x disableguardduty.py enableguardduty.py
</code>

You can then customize your scripts to add your own accounts and then execute them.

