# amazon-guardduty-multiaccount-scripts

These scripts automate the process of enabling and disabling Amazon GuardDuty simultaneously across a group of AWS accounts that are in your control. (Note, that you can have one master account and up to a 1000 member accounts).

> [!IMPORTANT]
> GuardDuty recommends using AWS Organizations instead of GuardDuty invitations to manage your member accounts. These scripts use GuardDuty's legacy invitation method. See https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_accounts.html for more information.

enableguardduty.py will enable GuardDuty, send invitations from the master account and accept invitations in all member accounts. The result will be a master account that contains all security findings for all member accounts. Since GuardDuty is regionally isolated, findings for each member account will roll up to the corresponding region in the master account. For example, the us-east-1 region in your GuardDuty master account will contain the security findings for all us-east-1 findings from all associated member accounts.

Note: Account owners of member accounts will receive an email for each region requesting that they accept the invitation to link their accounts, these emails can be ignored as the script accepts the invitation on their behalf.

## Prerequisites

* The scripts depend on a pre-existing role in the master account and all of the member accounts that will be linked, the role name must be the same in all accounts and the role trust relationship needs to allow your instance or local credentials to assume the role.  The AmazonGuardDutyFullAccess managed policy (shown below) contains the required permissions for the script to succeed:

``` 
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "guardduty:*",
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": "iam:CreateServiceLinkedRole",
            "Resource": "*",
            "Condition": {
                "StringLike": {
                    "iam:AWSServiceName": [
                        "guardduty.amazonaws.com",
                        "malware-protection.guardduty.amazonaws.com"
                    ]
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "organizations:EnableAWSServiceAccess",
                "organizations:RegisterDelegatedAdministrator",
                "organizations:ListDelegatedAdministrators",
                "organizations:ListAWSServiceAccessForOrganization",
                "organizations:DescribeOrganizationalUnit",
                "organizations:DescribeAccount",
                "organizations:DescribeOrganization"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": "iam:GetRole",
            "Resource": "arn:aws:iam::*:role/*AWSServiceRoleForAmazonGuardDutyMalwareProtection"
        }
    ]
}
```

If you do not have a common role that includes at least the above permissions you will need to create a role in each member account as well as the master account with at least the above permissions.  When creating the role ensure you use the same role name in every account and select the AmazonGuardDutyFullAccess managed policy.  You can use the EnableGuardDuty.yaml CloudFormation Template to automate this process, as the tempalte creates only global resources it can be created in any region.    

* A CSV file that includes the list of accounts to be linked to the master account.  Accounts should be listed one per line in the format of AccountId,EmailAddress.  The EmailAddress must be the email associated with the root account.
* Master AccountId which will recieve findings for all the linked accounts within the CSV file 

## Steps
### 1. Setup execution environment:
#### Option 1: Launch EC2 instance:
* Launch ec2 instance in your master account https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EC2_GetStarted.html
* Attach an IAM role to an instance that has permissions to allow the instance to call AssumeRole within the master account, if you used the EnableGuardDuty.yaml template an instance role with a profile name of "EnableGuardDuty" has been created, otherwise see the documentation on creating an instance role here:  https://aws.amazon.com/blogs/security/easily-replace-or-attach-an-iam-role-to-an-existing-ec2-instance-by-using-the-ec2-console/ on creating an instance role.
* Install required software
    * APT: sudo apt-get -y install python2-pip python2 git
    * RPM: sudo yum -y install python2-pip python2 git
    * sudo pip install boto3
* Clone the Repository
    * git clone https://github.com/aws-samples/amazon-guardduty-multiaccount-scripts.git
* Copy the CSV containing the account number and email addresses to the instance using one of the methods below
    * S3 `s3 cp s3://bucket/key_name enable.csv .`
    * pscp.exe `pscp local_file_path username@hostname:.`
    * scp `scp local_file_path username@hostname:.`

#### Option 2: Locally:
* Ensure you have credentials setup on your local machine for your master account that have permission to call AssumeRole.
* Install Required Software:
    * Windows:
        * Install Python https://www.python.org/downloads/windows/
        * Open command prompt:
            * pip install boto3
        * Download sourcecode from https://github.com/aws-samples/amazon-guardduty-multiaccount-scripts
        * Change directory of command prompt to the newly downloaded amazon-guardduty-multiaccount-scripts folder
    * Mac:
        * Install Python https://www.python.org/downloads/mac-osx/
        * Open command prompt:
            * pip install boto3
        * Download sourcecode from https://github.com/aws-samples/amazon-guardduty-multiaccount-scripts
        * Change directory of command prompt to the newly downloaded amazon-guardduty-multiaccount-scripts folder
    * Linux:
        * sudo apt-get -y install install python2-pip python2 git
        * sudo pip install boto3
        * git clone https://github.com/aws-samples/amazon-guardduty-multiaccount-scripts
        * cd amazon-guardduty-multiaccount-scripts
        Or
        * sudo yum install git python
        * sudo pip install boto3
        * git clone https://github.com/aws-samples/amazon-guardduty-multiaccount-scripts
        * cd amazon-guardduty-multiaccount-scripts

### 2. Execute Scripts
#### 2a. Enable GuardDuty
* Copy the required CSV file to this directory
    * Should be in the formation of "AccountId,EmailAddress" with one AccountID and EmailAddress per line.

```
usage: enableguardduty.py [-h] --master_account MASTER_ACCOUNT --assume_role
                          ASSUME_ROLE
                          input_file

Link AWS Accounts to central GuardDuty Account

positional arguments:
  input_file            Path to CSV file containing the list of account IDs
                        and Email addresses

optional arguments:
  -h, --help            show this help message and exit
  --master_account MASTER_ACCOUNT
                        AccountId for Central AWS Account
  --assume_role ASSUME_ROLE
                        Role Name to assume in each account
  
```
    
#### 2b. Disable GuardDuty
* Copy the required CSV file to this directory
    * Should be in the formation of "AccountId,EmailAddress,..."

```
usage: disableguardduty.py [-h] --master_account MASTER_ACCOUNT --assume_role
                           ASSUME_ROLE [--delete_master]
                           input_file

Link AWS Accounts to central GuardDuty Account

positional arguments:
  input_file            Path to CSV file containing the list of account IDs
                        and Email addresses

optional arguments:
  -h, --help            show this help message and exit
  --master_account MASTER_ACCOUNT
                        AccountId for Central AWS Account
  --assume_role ASSUME_ROLE
                        Role Name to assume in each account
  --delete_master       Delete the master Gd Detector
```

#### 2b. Change GuardDuty Features

Guardduty has multiple optional detection features that can be edited on a per-account basis. 

`updatefeature.py` allows you to toggle these on and off in bulk. Note that this only works on accounts
that are already enabled and associated with `enableguardduty.py`. 

For any given feature, `enable_<feature>` will turn it on, `disable_<feature>` will turn it off. If a 
flag for a `<feature>` is not provided, the previous value will be kept, which can be enabled _or_ disabled.

```
usage: updatefeature.py [-h] --master_account MASTER_ACCOUNT --assume_role ASSUME_ROLE [--enabled_regions ENABLED_REGIONS] [--enable_malware [ENABLE_MALWARE]] [--enable_eks [ENABLE_EKS]] [--enable_s3 [ENABLE_S3]] [--disable_malware [DISABLE_MALWARE]] [--disable_eks [DISABLE_EKS]]
                        [--disable_s3 [DISABLE_S3]] [--debug]
                        input_file

Link AWS Accounts to central GuardDuty Account

positional arguments:
  input_file            Path to CSV file containing the list of account IDs and Email addresses

optional arguments:
  -h, --help            show this help message and exit
  --master_account MASTER_ACCOUNT
                        AccountId for Central AWS Account
  --assume_role ASSUME_ROLE
                        Role Name to assume in each account
  --enabled_regions ENABLED_REGIONS
                        comma separated list of regions to enable GuardDuty. If not specified, all available regions enabled
  --enable_malware [ENABLE_MALWARE]
                        Enables GuardDuty Malware Protection
  --enable_eks [ENABLE_EKS]
                        Enables GuardDuty for EKS
  --enable_s3 [ENABLE_S3]
                        Enables GuardDuty S3 Protection
  --disable_malware [DISABLE_MALWARE]
                        Disable GuardDuty Malware Protection
  --disable_eks [DISABLE_EKS]
                        Disable GuardDuty for EKS
  --disable_s3 [DISABLE_S3]
                        Disable GuardDuty S3 Protection
  --debug               Turns on more verbose logging
```
