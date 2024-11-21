import boto3
import json

# Initialize the IAM client
iam_client = boto3.client('iam')

# Group and role details
GROUP_NAME = 'Developers'
ROLE_NAME_S3 = 'AssumeRoleForS3'
ROLE_NAME_EC2 = 'AssumeRoleForEC2'
ROLE_NAME_LAMBDA = 'AssumeRoleForLambda'

# Constants for services
SERVICE_ACCESS_TO_ROLE = {
    'S3': ROLE_NAME_S3,
    'EC2': ROLE_NAME_EC2,
    'Lambda': ROLE_NAME_LAMBDA
}

def get_user_arns_from_group(group_name):
    """
    Retrieves the ARNs of all users in the specified IAM group.
    """
    user_arns = []
    response = iam_client.get_group(GroupName=group_name)
    while True:
        user_arns.extend([user['Arn'] for user in response['Users']])
        if response['IsTruncated']:
            response = iam_client.get_group(GroupName=group_name, Marker=response['Marker'])
        else:
            break
    return user_arns

def get_user_service_access(user_arn):
    """
    Retrieves the ServiceAccess tag for a given user, handling multiple services if present.
    """
    user_name = user_arn.split('/')[-1]
    response = iam_client.list_user_tags(UserName=user_name)
    for tag in response['Tags']:
        if tag['Key'] == 'ServiceAccess':
            # Split the tag value by underscores to support multiple services
            return [service.strip() for service in tag['Value'].split('_')]
    return []

def create_role_if_not_exists(role_name, service_name):
    """
    Checks if the IAM role exists; if not, creates it with a basic trust policy for the specified service.
    """
    try:
        iam_client.get_role(RoleName=role_name)
    except iam_client.exceptions.NoSuchEntityException:
        # Role doesn't exist, so create it
        assume_role_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": service_name
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }
        iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(assume_role_policy)
        )

def update_trust_policy(role_name, user_arns, service_name='ec2.amazonaws.com'):
    """
    Updates or creates the trust policy of the specified role to include specified user ARNs.
    """
    # Check if role exists, create if not
    create_role_if_not_exists(role_name, service_name)

    # Base trust policy allowing EC2 or any other specified service to assume the role
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": service_name
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }
    
    if user_arns:
        # Add user ARNs to the trust policy
        trust_policy["Statement"].append({
            "Effect": "Allow",
            "Principal": {
                "AWS": user_arns
            },
            "Action": "sts:AssumeRole"
        })

    iam_client.update_assume_role_policy(
        RoleName=role_name,
        PolicyDocument=json.dumps(trust_policy)
    )

def lambda_handler(event, context):
    # Retrieve current user ARNs from the group
    current_user_arns = get_user_arns_from_group(GROUP_NAME)
    
    # Separate user ARNs based on their ServiceAccess tag
    service_to_user_arns = {
        'S3': [],
        'EC2': [],
        'Lambda': []
    }
    
    for user_arn in current_user_arns:
        service_access_tags = get_user_service_access(user_arn)
        for service_access_tag in service_access_tags:
            if service_access_tag in service_to_user_arns:
                service_to_user_arns[service_access_tag].append(user_arn)
    
    # Update trust policies for each role based on user tags
    for service, role_name in SERVICE_ACCESS_TO_ROLE.items():
        update_trust_policy(role_name, service_to_user_arns[service], f"{service.lower()}.amazonaws.com")
    
    message = "Trust policies updated for roles based on user tags."
    return {
        'statusCode': 200,
        'body': json.dumps(message)
    }