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

        sg_ids=$(aws ec2 describe-security-groups --region $region --filters "Name=vpc-id,Values=$default_vpc_id" "Name=group-name,Values=default" --query 'SecurityGroups[?GroupName=='default'].GroupId' --output text)
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

        rt_ids=$(aws ec2 describe-route-tables --region $region --filters "Name=vpc-id,Values=$default_vpc_id" --query 'RouteTables[].RouteTableId' --output text)
        for rt_id in $rt_ids; do
            echo "Deleting route table associations in region $region"
            associations=$(aws ec2 describe-route-tables --region $region --route-table-id $rt_id --query 'RouteTables[].Associations[?Main!=`true`].RouteTableAssociationId' --output text)
            for assoc_id in $associations; do
                aws ec2 disassociate-route-table --region $region --association-id $assoc_id
            done
            echo "Deleting route table $rt_id in region $region"
            aws ec2 delete-route-table --region $region --route-table-id $rt_id
        done

        echo "Deleting VPC $default_vpc_id in region $region"
        aws ec2 delete-vpc --region $region --vpc-id $default_vpc_id
    done
}

create_ra() {
    PROVIDER_NAME="GAPSSO2"
    METADATA_FILE="KeycloakGAPSSO.xml"
    METADATA_URL="https://raw.githubusercontent.com/G-AsiaPacific/AWS-Federated-SSO-V2/main/KeycloakGAPSSO.xml"
}

create_iam_role() {
    while true; do
        echo "Customer Name (without space) - *If PMA then starts with 'PMA-CustomerName' else 'CustomerName':"
        read CUSTOMER_NAME_INPUT
        if [ -z "$CUSTOMER_NAME_INPUT" ]; then
            echo 'Inputs cannot be blank, please try again!'
        elif [[ "$CUSTOMER_NAME_INPUT" == *" "* ]]; then
            CUSTOMER_NAME_INPUT=${CUSTOMER_NAME_INPUT// /-}
            echo "Input contains spaces. Replaced spaces with '-': $CUSTOMER_NAME_INPUT"
            echo "Do you agree with this change? (yes/NO)"
            read AGREEMENT
            if [[ "$AGREEMENT" =~ ^(yes|YES|y|Y)$ ]]; then
                break
            else
                echo "Please enter the Customer Name again without spaces."
            fi
        else
            break
        fi
    done

    echo 'Creating IAM Roles and IDP Provider...'
    CUSTOMER_NAME=$CUSTOMER_NAME_INPUT
    CUSTOMER_NAME_FOR_DESCRIPTION=$(echo "$CUSTOMER_NAME_INPUT" | tr '-' '\040' | tr _ ' ')
    ACCOUNT_ID=$(aws sts get-caller-identity | jq -r .Account)
    curl --silent -o $METADATA_FILE $METADATA_URL
    IDP_ARN=$(aws iam create-saml-provider --saml-metadata-document file://$METADATA_FILE --name $PROVIDER_NAME --query 'SAMLProviderArn')
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

    aws iam get-role --role-name $Tech_ROLE_NAME > /dev/null 2>&1
    if [ $? -ne 0 ]; then
    echo "Error: Role '$Tech_ROLE_NAME' does not exist. Creating a new role..."
        TECH_ROLE_ARN=$(aws iam create-role --role-name $Tech_ROLE_NAME --assume-role-policy-document file://$TRUST_RELATIONSHIP_FILE --query 'Role.Arn' --max-session-duration 43200)
    else
        echo "Role '$Tech_ROLE_NAME' already exists. Updating its Trust Relationship to utilize GAPSSO2..."
        aws iam update-role-trust-policy --role-name $Tech_ROLE_NAME --policy-document file://$TRUST_RELATIONSHIP_FILE
    fi

    aws iam get-role --role-name $Tech_ROLE_NAME > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "Error: Role '$Tech_ROLE_NAME' does not exist. Creating a new role..."
        BILLING_ROLE_ARN=$(aws iam create-role --role-name $Billing_ROLE_NAME --assume-role-policy-document file://$TRUST_RELATIONSHIP_FILE --query 'Role.Arn')
    else
        echo "Role '$Tech_ROLE_NAME' already exists. Updating its Trust Relationship to utilize GAPSSO2..."
        aws iam update-role-trust-policy --role-name $Billing_ROLE_NAME --policy-document file://$TRUST_RELATIONSHIP_FILE
    fi
    
    aws iam put-role-policy --role-name $Billing_ROLE_NAME --policy-name CostExplorerPolicy --policy-document file://$COST_EXPLORER_FILE
    aws iam attach-role-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess --role-name $Tech_ROLE_NAME
    aws iam attach-role-policy --policy-arn arn:aws:iam::aws:policy/job-function/Billing --role-name $Tech_ROLE_NAME
    aws iam attach-role-policy --policy-arn arn:aws:iam::aws:policy/job-function/Billing --role-name $Billing_ROLE_NAME
    aws iam attach-role-policy --policy-arn arn:aws:iam::aws:policy/AWSSupportAccess --role-name $Billing_ROLE_NAME
    aws iam attach-role-policy --policy-arn arn:aws:iam::aws:policy/AWSSavingsPlansFullAccess --role-name $Billing_ROLE_NAME
    rm $TRUST_RELATIONSHIP_FILE $COST_EXPLORER_FILE $METADATA_FILE
}

check_region() {
    echo "[0] Malaysia"
    echo "[1] Singapore"
    echo "[2] Indonesia"
    echo "[3] Vietnam"
    read -p "Enter your choice (0-3): " check_region

    case $check_region in
        0) ACCOUNT_REGION="Malaysia";;
        1) ACCOUNT_REGION="Singapore";;
        2) ACCOUNT_REGION="Indonesia";;
        3) ACCOUNT_REGION="Vietnam";;
        *) echo "Invalid input. Try again!"
    esac
}

check_type_account() {
    echo "[0] AWS Root Account (RA)"
    echo "[1] AWS PMA Account"
    echo "[2] AWS Billing Transfer Account"
    read -p "Enter your account type (0 - 2): " choose_type_account
    case $choose_type_account in
        0) create_ra; create_iam_role; check_region; delete_default_vpc ;;
        1) create_ra; create_iam_role; check_region ;;
        2) create_ra; create_iam_role; check_region ;;
        *) echo 'Sorry, try again' >&2 ;;
    esac
    echo 'Below are the roles for Keycloak realm roles registration:'
    if [ $choose_type_account -eq 1 ]; then
        echo ${TECH_ROLE_ARN//\"/}','${IDP_ARN//\"/}
        echo 'Technical Role for AWS PMA Account'${CUSTOMER_NAME_FOR_DESCRIPTION##*PMA} '('${CUSTOMER_NAME_FOR_DESCRIPTION##*PMA}' '$ACCOUNT_REGION' )'
        echo ${BILLING_ROLE_ARN//\"/}','${IDP_ARN//\"/}
        echo 'Billing Role for AWS PMA Account'${CUSTOMER_NAME_FOR_DESCRIPTION##*PMA} '('${CUSTOMER_NAME_FOR_DESCRIPTION##*PMA}' '$ACCOUNT_REGION' )'
    else
        echo ${TECH_ROLE_ARN//\"/}','${IDP_ARN//\"/}
        echo 'Technical Role for '$CUSTOMER_NAME_FOR_DESCRIPTION' '$ACCOUNT_REGION
        echo ${BILLING_ROLE_ARN//\"/}','${IDP_ARN//\"/}
        echo 'Billing Role for '$CUSTOMER_NAME_FOR_DESCRIPTION' '$ACCOUNT_REGION
    fi
}

check_type_account
