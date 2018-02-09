# amazon-guardduty-multiaccount-scripts

These scripts automate the process of enabling and disabling Amazon GuardDuty simultaneously across a group of AWS accounts that are in your control. (Note, that you can have one master account and up to a 1000 member accounts).enableguardduty.py will enable GuardDuty, send invitations from the master account and accept invitations in all member accounts. The result will be a master account that contains all security findings for all member accounts. Since GuardDuty is regionally isolated, findings for each member account will roll up to the corresponding region in the master account. For example, the us-east-1 region in your GuardDuty master account will contain the security findings for all us-east-1 findings from all associated member accounts.

## Prerequisites

The scripts are modelled with the StackSets service in mind and are therefore dependent on having the IAM role called AWSCloudFormationStackSetExecutionRole in each account where you want to enable GuardDuty. This role provides StackSets with access to GuardDuty. 
If you are already using StackSets, the scripts can leverage your existing roles. If not, you can use the instructions in https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-prereqs.html to setup the AWSCloudFormationStackSetExecutionRole in each account where you want to enable GuardDuty.

## Step 1

Launch a new Amazon Linux instance with a role that has administrative permissions. Login to this instance and run the following commands:

sudo yum install git python
sudo pip install boto3
aws configure
Note: set the region to us-east-1 or whatever default region you want
git clone https://github.com/aws-samples/amazon-guardduty-multiaccount-scripts.git
cd amazon-guardduty-multiaccount-scripts
sudo chmod +x disableguardduty.py enableguardduty.py

## Step 2
The script has one parameter - the account ID of your GuardDuty master account.
Before you execute enableguardduty.py and/or disableguardduty.py, update either script’s global variables to map to your AWS accounts. You will need to create a list of the accounts and their associated email addresses. You will specify the master account and you can also customize the invite message that is sent if you'd like to.

