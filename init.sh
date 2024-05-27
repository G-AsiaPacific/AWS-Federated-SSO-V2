#!/usr/bin/env bash
#set -e

delete_default_vpc() {
    echo "Fetching Enabled Regions"
    enabled_regions=$(aws ec2 describe-regions --query 'Regions[?OptInStatus==`opt-in-not-required` || OptInStatus==`opted-in`].RegionName' --output text)

    echo "Deleting default VPCs, Subnets, Security Groups, etc."
    for region in $enabled_regions; do
        echo "Working in region $region"
        default_vpc_id=$(aws ec2 describe-vpcs --region $region --filters "Name=is-default,Values=true" --query 'Vpcs[0].VpcId' --output text)
        if [ "$default_vpc_id" == "None" ]; then
            echo "No default VPC in region $region"
            continue
        fi
        subnet_ids=$(aws ec2 describe-subnets --region $region --filters "Name=vpc-id,Values=$default_vpc_id" --query 'Subnets[].SubnetId' --output text)
        for id in $subnet_ids; do
            echo "Deleting subnet $id in region $region"
            aws ec2 delete-subnet --region $region --subnet-id $id
        done
        sg_ids=$(aws ec2 describe-security-groups --region $region --filters "Name=vpc-id,Values=$default_vpc_id" "Name=group-name,Values=default" --query 'SecurityGroups[?GroupName=='default'].GroupId[]' --output text)
        for id in $sg_ids; do
            echo "Deleting security group $id in region $region"
            aws ec2 delete-security-group --region $region --group-id $id
        done
        igw_ids=$(aws ec2 describe-internet-gateways --region $region --filters "Name=attachment.vpc-id,Values=$default_vpc_id" --query 'InternetGateways[].InternetGatewayId' --output text)
        for id in $igw_ids; do
            echo "Detaching and deleting internet gateway $id in region $region"
            aws ec2 detach-internet-gateway --region $region --internet-gateway-id $id --vpc-id $default_vpc_id
            aws ec2 delete-internet-gateway --region $region --internet-gateway-id $id
        done
        rt_ids=$(aws ec2 describe-route-tables --region $region --filters "Name=vpc-id,Values=$default_vpc_id" --query 'RouteTables[?Associations[0].Main==`true`].RouteTableId' --output text)
        for id in $rt_ids; do
            echo "Deleting route table $id in region $region"
            aws ec2 delete-route-table --region $region --route-table-id $id
        done
        nacl_ids=$(aws ec2 describe-network-acls --region $region --filters "Name=vpc-id,Values=$default_vpc_id" --query 'NetworkAcls[?IsDefault==`true`].NetworkAclId' --output text)
        for id in $nacl_ids; do
            echo "Deleting network acl $id in region $region"
            aws ec2 delete-network-acl --region $region --network-acl-id $id
        done
        echo "Deleting VPC $default_vpc_id in region $region"
        aws ec2 delete-vpc --region $region --vpc-id $default_vpc_id
    done
}

create_pma() {
    PROVIDER_NAME="GoogleSSO"
    METADATA_FILE="GoogleIDPMetadata.xml"
    METADATA_URL="https://raw.githubusercontent.com/G-AsiaPacific/AWS-Federated-SSO-V2/main/GoogleIDPMetadata.xml"
}

create_ra() {
    PROVIDER_NAME="GAPSSO2"
    METADATA_FILE="KeycloakGAPSSO.xml"
    METADATA_URL="https://raw.githubusercontent.com/G-AsiaPacific/AWS-Federated-SSO-V2/main/KeycloakGAPSSO.xml"
}

create_iam_role() {
    echo "Customer Name (without space):"
    read CUSTOMER_NAME_INPUT
    if [ -z "$CUSTOMER_NAME_INPUT" ]; then echo 'Inputs cannot be blank please try again!'; exit 0; fi
    CUSTOMER_NAME=$CUSTOMER_NAME_INPUT
    ACCOUNT_ID=$(aws sts get-caller-identity | jq -r .Account)
    curl --silent -o $METADATA_FILE $METADATA_URL
    aws iam create-saml-provider --saml-metadata-document file://$METADATA_FILE --name $PROVIDER_NAME --query 'SAMLProviderArn'
    Tech_ROLE_NAME=$CUSTOMER_NAME"-SSO-Tech"
    Billing_ROLE_NAME=$CUSTOMER_NAME"-SSO-Billing"
    TRUST_RELATIONSHIP_FILE="trust-relationship.json"
    cat > $TRUST_RELATIONSHIP_FILE << EOL
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::$ACCOUNT_ID:saml-provider/$PROVIDER_NAME"
      },
      "Action": "sts:AssumeRoleWithSAML",
      "Condition": {
        "StringEquals": {
          "SAML:aud": "https://signin.aws.amazon.com/saml"
        }
      }
    }
  ]
}
EOL
    COST_EXPLORER_FILE="costexplorerpolicy.json"
    cat > $COST_EXPLORER_FILE << EOL
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "costexplorerpolicy",
      "Effect": "Allow",
      "Action": [
        "ce:*"
      ],
      "Resource": "*"
    }
  ]
}
EOL
    aws iam create-role --role-name $Tech_ROLE_NAME --assume-role-policy-document file://$TRUST_RELATIONSHIP_FILE --query 'Role.Arn' --max-session-duration 43200
    aws iam create-role --role-name $Billing_ROLE_NAME --assume-role-policy-document file://$TRUST_RELATIONSHIP_FILE --query 'Role.Arn'
    aws iam put-role-policy --role-name $Billing_ROLE_NAME --policy-name CostExplorerPolicy --policy-document file://$COST_EXPLORER_FILE
    aws iam attach-role-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess --role-name $Tech_ROLE_NAME
    aws iam attach-role-policy --policy-arn arn:aws:iam::aws:policy/job-function/Billing --role-name $Tech_ROLE_NAME
    aws iam attach-role-policy --policy-arn arn:aws:iam::aws:policy/job-function/Billing --role-name $Billing_ROLE_NAME
    aws iam attach-role-policy --policy-arn arn:aws:iam::aws:policy/AWSSupportAccess --role-name $Billing_ROLE_NAME
    rm $TRUST_RELATIONSHIP_FILE $COST_EXPLORER_FILE $METADATA_FILE
}

check_type_account() {
    echo "[0] AWS Root Account (RA)"
    echo "[1] AWS PMA Account"
    read choose_type_account
    case $choose_type_account in
        0) create_ra; create_iam_role; delete_default_vpc ;;
        1) create_pma; create_iam_role ;;
        *) echo 'Sorry, try again' >&2 ;;
    esac
}

check_type_account
