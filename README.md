# amazon-guardduty-multiaccount-scripts

These scripts automate the process of enabling and disabling Amazon GuardDuty simultaneously across a group of AWS accounts that are in your control. (Note, that you can have one master account and up to a 1000 member accounts).

enableguardduty.py will enable GuardDuty, send invitations from the master account and accept invitations in all member accounts. The result will be a master account that contains all security findings for all member accounts. Since GuardDuty is regionally isolated, findings for each member account will roll up to the corresponding region in the master account. For example, the us-east-1 region in your GuardDuty master account will contain the security findings for all us-east-1 findings from all associated member accounts.

## Prerequisites

* The scripts depend on a pre-existing role that can be utilized within each account.  The StackSets service role AWSCloudFormationStackSetExecutionRole is utilized by default.  Instructions can be found here: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-prereqs.html to setup the role in each account
* CSV file for accounts to be added in the format of AccountId, Email, ...
* Master AccountId for all accounts within the CSV file to be linked to

## Steps
### 1. Setup execution environment:
#### Option 1: Launch EC2 instance:
* launch ec2 instance https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EC2_GetStarted.html
* assign role https://aws.amazon.com/blogs/security/easily-replace-or-attach-an-iam-role-to-an-existing-ec2-instance-by-using-the-ec2-console/
* Install required software
    * sudo apt-get -y install python2-pip python2 git
    * sudo pip install boto3
* Clone the Repository
    * git clone https://github.com/aws-samples/amazon-guardduty-multiaccount-scripts.git
* Copy the CSV containing accounts
    * S3 `s3 cp s3://bucket/key_name enable.csv`
    * pscp.exe `pscp local_file_path username@hostname:/tmp`
    * scp `scp local_file_path username@hostname:/tmp`

#### Option 2: Locally:
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
    * Should be in the formation of "AccountId,EmailAddress,..."

```
usage: python enableguardduty.py [-h] [--master_account MASTER_ACCOUNT]
                                 [--assume_role ASSUME_ROLE]
                                 input_file

Link AWS Accounts to central GuardDuty Account

positional arguments:
  input_file            Path to CSV file in the format of accountId, email,
                        ...

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
usage: disableguardduty.py [-h] [--master_account MASTER_ACCOUNT]
                           [--assume_role ASSUME_ROLE] [--delete_master]
                           input_file

Link AWS Accounts to central GuardDuty Account

positional arguments:
  input_file            Path to CSV file in the format of accountId, email,
                        ...

optional arguments:
  -h, --help            show this help message and exit
  --master_account MASTER_ACCOUNT
                        AccountId for Central AWS Account
  --assume_role ASSUME_ROLE
                        Role Name to assume in each account
  --delete_master       Delete the master Gd Detector
```
