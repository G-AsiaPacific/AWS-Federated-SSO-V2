# AWS-Federated-SSO-V2

This script automates the setup for AWS Federated Single Sign-On (SSO) by creating necessary IAM roles and policies. It supports both PMA and Root Account configurations. The script also includes functionality to clean up default VPCs across all AWS regions, providing a cleaner environment for your AWS setup.

## How to Use

### Prerequisites

- AWS CLI must be installed and configured with necessary access permissions.
- jq must be installed.

### Getting Started

1. **Open AWS CloudShell**: Log into your AWS account and open CloudShell. This provides a ready-to-use environment with AWS CLI and jq already installed.

2. **Download the Script**: Use the `curl` command to download the script from the GitHub repository.

    ```bash
    curl --silent -o init.sh https://raw.githubusercontent.com/G-AsiaPacific/AWS-Federated-SSO-V2/main/init.sh
    ```

3. **Run the Script**: Make the script executable and run it.

    ```bash
    bash ./init.sh
    ```

4. **Follow Prompts**: The script will ask you to decide whether it's a PMA or a Root Account. Make your selection according to your AWS account setup.

5. **Enter Account Name**: When prompted, enter a name for your account setup. This name will be used to create IAM roles and policies.

The script will then proceed to create the necessary IAM roles for AWS Federated SSO and perform any additional setup steps, such as cleaning up default VPCs if applicable.

### Important Notes

- Ensure you have the necessary permissions to create IAM roles and policies and modify VPC settings in your AWS account.
- Running this script may result in changes to your AWS account's IAM and VPC configuration. It's recommended to review the script and understand the changes it makes before running it in a production environment.
