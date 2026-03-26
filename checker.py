import boto3
import json
import os
import csv
from datetime import datetime
from botocore.exceptions import ClientError, NoCredentialsError
from dotenv import load_dotenv

# Load environment variables from the .env file for local development
load_dotenv()

# --- Load AWS Resource Identifiers from Environment Variables ---
# These IDs scope the scan to the specific test environment resources.
VPC_ID = os.getenv("AWS_VPC_ID")
PUBLIC_SUBNET_ID = os.getenv("AWS_PUBLIC_SUBNET_ID")
PRIVATE_SUBNET_ID = os.getenv("AWS_PRIVATE_SUBNET_ID")
ROUTE_TABLE_ID = os.getenv("AWS_ROUTE_TABLE_ID")
IGW_ID = os.getenv("AWS_IGW_ID")
PERMISSIVE_ACL_ID = os.getenv("AWS_PERMISSIVE_ACL_ID")

# Get regions to scan (defaults to eu-north-1 if not specified)
REGIONS = os.getenv("AWS_REGIONS", "eu-north-1").split(",")

# Initialize global IAM client (IAM is region-independent)
iam_client = boto3.client('iam')

# Initialize boto3 clients for AWS services
def get_clients(region):
    """Initialize AWS service clients for a specific region"""
    return {
        's3': boto3.client('s3', region_name=region),
        'ec2': boto3.client('ec2', region_name=region),
        'iam': iam_client,  # IAM is global
        'rds': boto3.client('rds', region_name=region),
        'cloudtrail': boto3.client('cloudtrail', region_name=region)
    }


# --- S3 Compliance Checks ---
def check_s3_compliance(s3_client):
    issues = []
    try:
        buckets = s3_client.list_buckets().get('Buckets', [])
    except (ClientError, NoCredentialsError) as e:
        return [{"Bucket": "N/A", "Issues": [{"Issue": f"Error accessing S3: {str(e)}", "DORA_Mapping": "N/A", "Severity": "High"}]}]
    
    for bucket in buckets:
        bucket_name = bucket['Name']
        bucket_issue = {"Bucket": bucket_name, "Issues": []}
        
        # Check Public Access Block configuration
        try:
            pab = s3_client.get_public_access_block(Bucket=bucket_name)
            config = pab.get('PublicAccessBlockConfiguration', {})
            if not (config.get('BlockPublicAcls', True) and 
                    config.get('IgnorePublicAcls', True) and 
                    config.get('BlockPublicPolicy', True) and 
                    config.get('RestrictPublicBuckets', True)):
                bucket_issue["Issues"].append({
                    "Issue": "Public access is allowed due to misconfigured Public Access Block settings.",
                    "DORA_Mapping": "Article 9 (Secure Cloud Configurations)",
                    "Severity": "Critical"
                })
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                bucket_issue["Issues"].append({
                    "Issue": "No Public Access Block configuration found.",
                    "DORA_Mapping": "Article 9 (Secure Cloud Configurations)",
                    "Severity": "Critical"
                })
            else:
                raise

        # Check the bucket policy for public access
        try:
            policy = s3_client.get_bucket_policy(Bucket=bucket_name)
            policy_doc = json.loads(policy['Policy'])
            for statement in policy_doc.get("Statement", []):
                principal = statement.get("Principal")
                if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                    bucket_issue["Issues"].append({
                        "Issue": "Bucket policy allows public access.",
                        "DORA_Mapping": "Article 9 (Secure Cloud Configurations)",
                        "Severity": "Critical"
                    })
                    break
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                # No policy exists, which is secure in this context.
                pass
            else:
                raise

        # Check if server-side encryption is enabled
        try:
            s3_client.get_bucket_encryption(Bucket=bucket_name)
        except ClientError as e:
            if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
                bucket_issue["Issues"].append({
                    "Issue": "Bucket encryption is not enabled.",
                    "DORA_Mapping": "Article 9 (Secure Cloud Configurations)",
                    "Severity": "High"
                })

        # Check if versioning is enabled
        try:
            versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
            if versioning.get('Status') != 'Enabled':
                bucket_issue["Issues"].append({
                    "Issue": "Bucket versioning is not enabled.",
                    "DORA_Mapping": "Article 9 (Secure Cloud Configurations)",
                    "Severity": "Medium"
                })
        except ClientError:
            pass

        # Check if server access logging is enabled
        try:
            logging = s3_client.get_bucket_logging(Bucket=bucket_name)
            if not logging.get("LoggingEnabled"):
                bucket_issue["Issues"].append({
                    "Issue": "Bucket logging is not enabled.",
                    "DORA_Mapping": "Article 10 (Incident Reporting & Security Governance)",
                    "Severity": "Medium"
                })
        except Exception as e:
            bucket_issue["Issues"].append({
                "Issue": "Error checking bucket logging: " + str(e),
                "DORA_Mapping": "Article 10 (Incident Reporting & Security Governance)",
                "Severity": "Low"
            })

        if bucket_issue["Issues"]:
            issues.append(bucket_issue)
    return issues


# --- EC2 Security Group Checks ---
def check_ec2_security_groups(ec2_client):
    issues = []
    try:
        # Filter security groups to only those within our specific test VPC if VPC_ID is set
        filters = [{'Name': 'vpc-id', 'Values': [VPC_ID]}] if VPC_ID else []
        sg_response = ec2_client.describe_security_groups(Filters=filters)
    except (ClientError, NoCredentialsError) as e:
        return [{"SecurityGroup": "N/A", "Issues": [{"Issue": f"Error accessing EC2: {str(e)}", "DORA_Mapping": "N/A", "Severity": "High"}]}]
    
    for sg in sg_response.get('SecurityGroups', []):
        sg_id = sg['GroupId']
        sg_issue = {"SecurityGroup": sg_id, "Issues": []}
        for rule in sg.get('IpPermissions', []):
            protocol = rule.get('IpProtocol')
            from_port = rule.get('FromPort')
            to_port = rule.get('ToPort')
            for ip_range in rule.get('IpRanges', []):
                cidr = ip_range.get('CidrIp')
                if cidr == '0.0.0.0/0':
                    if protocol == "tcp" and from_port is not None and to_port is not None:
                        if from_port <= 22 <= to_port:
                            sg_issue["Issues"].append({
                                "Issue": "SSH (port 22) publicly accessible",
                                "DORA_Mapping": "Article 9 (Secure Cloud Configurations)",
                                "Severity": "Critical"
                            })
                        if from_port <= 3389 <= to_port:
                            sg_issue["Issues"].append({
                                "Issue": "RDP (port 3389) publicly accessible",
                                "DORA_Mapping": "Article 9 (Secure Cloud Configurations)",
                                "Severity": "Critical"
                            })
                        if from_port <= 3306 <= to_port:
                            sg_issue["Issues"].append({
                                "Issue": "MySQL (port 3306) publicly accessible",
                                "DORA_Mapping": "Article 9 (Secure Cloud Configurations)",
                                "Severity": "Critical"
                            })
                        if from_port <= 5432 <= to_port:
                            sg_issue["Issues"].append({
                                "Issue": "PostgreSQL (port 5432) publicly accessible",
                                "DORA_Mapping": "Article 9 (Secure Cloud Configurations)",
                                "Severity": "Critical"
                            })
                        if from_port <= 80 <= to_port:
                            sg_issue["Issues"].append({
                                "Issue": "HTTP (port 80) publicly accessible",
                                "DORA_Mapping": "Article 9 (Secure Cloud Configurations)",
                                "Severity": "Medium"
                            })
                        if from_port <= 443 <= to_port:
                            sg_issue["Issues"].append({
                                "Issue": "HTTPS (port 443) publicly accessible - ensure WAF is configured",
                                "DORA_Mapping": "Article 9 (Secure Cloud Configurations)",
                                "Severity": "Low"
                            })
                    elif protocol == "icmp":
                        sg_issue["Issues"].append({
                            "Issue": "ICMP (Ping) publicly accessible",
                            "DORA_Mapping": "Article 9 (Secure Cloud Configurations)",
                            "Severity": "Low"
                        })
                    elif protocol == "-1":  # All protocols
                        sg_issue["Issues"].append({
                            "Issue": "All traffic (all protocols) publicly accessible",
                            "DORA_Mapping": "Article 9 (Secure Cloud Configurations)",
                            "Severity": "Critical"
                        })
        if sg_issue["Issues"]:
            issues.append(sg_issue)
    return issues


# --- IAM Compliance Checks ---
def policy_allows_wildcards(policy_doc):
    """
    Checks if a given IAM policy document contains wildcard "*" 
    in its Action or Resource fields.
    """
    statements = policy_doc.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]
    for stmt in statements:
        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        if "*" in actions or "*" in resources:
            return True
    return False

def check_user_activity(user):
    """
    Checks if an IAM user has used their password or access keys recently.
    Returns True if the user appears to be inactive.
    """
    # Assume the user is inactive until activity is found
    inactive = True

    # Check for console login activity
    if 'PasswordLastUsed' in user:
        inactive = False

    # Check for access key activity
    user_name = user['UserName']
    access_keys = iam_client.list_access_keys(UserName=user_name).get('AccessKeyMetadata', [])
    for key in access_keys:
        key_id = key['AccessKeyId']
        try:
            last_used_info = iam_client.get_access_key_last_used(AccessKeyId=key_id)
            if last_used_info.get('AccessKeyLastUsed', {}).get('LastUsedDate'):
                inactive = False
                break
        except ClientError:
            # If an error occurs (e.g., key never used), assume no activity for this key
            continue

    return inactive

def check_iam_policies():
    issues = []
    try:
        # Check IAM Roles for overly permissive policies
        roles = iam_client.list_roles().get('Roles', [])
    except (ClientError, NoCredentialsError) as e:
        return [{"Role": "N/A", "Issues": [{"Issue": f"Error accessing IAM: {str(e)}", "DORA_Mapping": "N/A", "Severity": "High"}]}]
    
    for role in roles:
        role_name = role['RoleName']
        role_issue = {"Role": role_name, "Issues": []}
        
        # Check inline policies attached to the role
        inline_policies = iam_client.list_role_policies(RoleName=role_name).get('PolicyNames', [])
        for policy_name in inline_policies:
            policy = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)['PolicyDocument']
            if policy_allows_wildcards(policy):
                role_issue["Issues"].append({
                    "Issue": f"Inline policy '{policy_name}' grants wildcard permissions.",
                    "DORA_Mapping": "Article 5 (ICT Risk Management & Third-Party Oversight)",
                    "Severity": "High"
                })
        
        # This is a simplified check for attached managed policies.
        # A full implementation would inspect the policy document of each managed policy.
        attached_policies = iam_client.list_attached_role_policies(RoleName=role_name).get('AttachedPolicies', [])
        for attached_policy in attached_policies:
            if "Administrator" in attached_policy['PolicyName']:
                role_issue["Issues"].append({
                    "Issue": f"Review attached policy '{attached_policy['PolicyName']}' for wildcard permissions.",
                    "DORA_Mapping": "Article 5 (ICT Risk Management & Third-Party Oversight)",
                    "Severity": "High"
                })
            
        if role_issue["Issues"]:
            issues.append(role_issue)
    
    # Check IAM Users for MFA status and inactivity
    users = iam_client.list_users().get('Users', [])
    for user in users:
        user_name = user['UserName']
        user_issue = {"User": user_name, "Issues": []}
        
        mfa_devices = iam_client.list_mfa_devices(UserName=user_name).get('MFADevices', [])
        if not mfa_devices:
            user_issue["Issues"].append({
                "Issue": "User does not have MFA enabled.",
                "DORA_Mapping": "Article 5 (ICT Risk Management & Third-Party Oversight)",
                "Severity": "High"
            })
        
        # Check if the user account has been inactive
        if check_user_activity(user):
            user_issue["Issues"].append({
                "Issue": "User account appears to be inactive (no console or API usage).",
                "DORA_Mapping": "Article 5 (ICT Risk Management & Third-Party Oversight)",
                "Severity": "Medium"
            })
            
        if user_issue["Issues"]:
            issues.append(user_issue)
    
    return issues


# --- VPC Configuration Checks ---
def check_vpc_configurations(ec2_client):
    issues = []
    try:
        # Filter Route Tables to our specific test VPC if VPC_ID is set
        filters = [{'Name': 'vpc-id', 'Values': [VPC_ID]}] if VPC_ID else []
        route_tables = ec2_client.describe_route_tables(Filters=filters).get('RouteTables', [])
    except (ClientError, NoCredentialsError) as e:
        return [{"VPC": "N/A", "Issues": [{"Issue": f"Error accessing VPC: {str(e)}", "DORA_Mapping": "N/A", "Severity": "High"}]}]
    
    for rt in route_tables:
        rt_id = rt['RouteTableId']
        rt_issue = {"RouteTable": rt_id, "Issues": []}
        for route in rt.get('Routes', []):
            if route.get('DestinationCidrBlock') == "0.0.0.0/0" and 'GatewayId' in route:
                gateway = route['GatewayId']
                if gateway.startswith("igw-"):
                    rt_issue["Issues"].append({
                        "Issue": "Default route to an Internet Gateway detected; verify if intended for public subnets.",
                        "DORA_Mapping": "Article 9 (Secure Cloud Configurations)",
                        "Severity": "Medium"
                    })
        if rt_issue["Issues"]:
            issues.append(rt_issue)

    # Filter Network ACLs to our test VPC and the specific permissive ACL
    acl_filters = [{'Name': 'vpc-id', 'Values': [VPC_ID]}] if VPC_ID else []
    if PERMISSIVE_ACL_ID:
        acl_filters.append({'Name': 'network-acl-id', 'Values': [PERMISSIVE_ACL_ID]})
    
    acls = ec2_client.describe_network_acls(Filters=acl_filters).get('NetworkAcls', [])
    for acl in acls:
        acl_id = acl['NetworkAclId']
        acl_issue = {"NetworkACL": acl_id, "Issues": []}
        for entry in acl.get('Entries', []):
            if entry.get('RuleAction') == 'allow' and entry.get('CidrBlock') == "0.0.0.0/0":
                acl_issue["Issues"].append({
                    "Issue": "Overly permissive rule allowing all traffic from 0.0.0.0/0 detected.",
                    "DORA_Mapping": "Article 9 (Secure Cloud Configurations)",
                    "Severity": "High"
                })
        if acl_issue["Issues"]:
            issues.append(acl_issue)
    
    # Filter Subnets to our specific test VPC
    subnet_filters = [{'Name': 'vpc-id', 'Values': [VPC_ID]}] if VPC_ID else []
    subnets = ec2_client.describe_subnets(Filters=subnet_filters).get('Subnets', [])
    for subnet in subnets:
        subnet_id = subnet['SubnetId']
        # Check if the subnet automatically assigns public IPs to instances
        if subnet.get('MapPublicIpOnLaunch', False):
            issues.append({
                "Subnet": subnet_id,
                "Issues": [{
                    "Issue": "Subnet is configured to automatically assign public IPs, which may indicate unintended public exposure.",
                    "DORA_Mapping": "Article 9 (Secure Cloud Configurations)",
                    "Severity": "Medium"
                }]
            })
    
    # Check if VPC Flow Logs are enabled for our test VPC
    flow_logs = ec2_client.describe_flow_logs().get('FlowLogs', [])
    vpc_flow_log_ids = {log['ResourceId'] for log in flow_logs}
    if VPC_ID and VPC_ID not in vpc_flow_log_ids:
        issues.append({
            "VPC": VPC_ID,
            "Issues": [{
                "Issue": "VPC Flow Logs are not enabled, which may hinder network traffic monitoring.",
                "DORA_Mapping": "Article 10 (Incident Reporting & Security Governance)",
                "Severity": "Medium"
            }]
        })
    
    return issues

# --- RDS Compliance Checks ---
def check_rds_compliance(rds_client):
    issues = []
    try:
        db_instances = rds_client.describe_db_instances().get('DBInstances', [])
    except (ClientError, NoCredentialsError) as e:
        return [{"DBInstance": "N/A", "Issues": [{"Issue": f"Error accessing RDS: {str(e)}", "DORA_Mapping": "N/A", "Severity": "High"}]}]
    
    for db in db_instances:
        db_id = db['DBInstanceIdentifier']
        db_issue = {"DBInstance": db_id, "Issues": []}
        
        # Check if publicly accessible
        if db.get('PubliclyAccessible', False):
            db_issue["Issues"].append({
                "Issue": "RDS instance is publicly accessible.",
                "DORA_Mapping": "Article 9 (Secure Cloud Configurations)",
                "Severity": "Critical"
            })
        
        # Check if encryption at rest is enabled
        if not db.get('StorageEncrypted', False):
            db_issue["Issues"].append({
                "Issue": "RDS instance does not have encryption at rest enabled.",
                "DORA_Mapping": "Article 9 (Secure Cloud Configurations)",
                "Severity": "High"
            })
        
        # Check if automated backups are enabled
        if db.get('BackupRetentionPeriod', 0) == 0:
            db_issue["Issues"].append({
                "Issue": "RDS instance does not have automated backups enabled.",
                "DORA_Mapping": "Article 10 (Incident Reporting & Security Governance)",
                "Severity": "High"
            })
        
        # Check if multi-AZ deployment is enabled
        if not db.get('MultiAZ', False):
            db_issue["Issues"].append({
                "Issue": "RDS instance is not configured for Multi-AZ deployment.",
                "DORA_Mapping": "Article 9 (Secure Cloud Configurations)",
                "Severity": "Medium"
            })
        
        if db_issue["Issues"]:
            issues.append(db_issue)
    
    return issues

# --- CloudTrail Compliance Checks ---
def check_cloudtrail_compliance(cloudtrail_client):
    issues = []
    try:
        trails = cloudtrail_client.describe_trails().get('trailList', [])
    except (ClientError, NoCredentialsError) as e:
        return [{"Trail": "N/A", "Issues": [{"Issue": f"Error accessing CloudTrail: {str(e)}", "DORA_Mapping": "N/A", "Severity": "High"}]}]
    
    if not trails:
        return [{
            "Trail": "N/A",
            "Issues": [{
                "Issue": "No CloudTrail trails configured in this region.",
                "DORA_Mapping": "Article 10 (Incident Reporting & Security Governance)",
                "Severity": "Critical"
            }]
        }]
    
    for trail in trails:
        trail_name = trail['Name']
        trail_issue = {"Trail": trail_name, "Issues": []}
        
        # Get trail status
        try:
            status = cloudtrail_client.get_trail_status(Name=trail['TrailARN'])
            if not status.get('IsLogging', False):
                trail_issue["Issues"].append({
                    "Issue": "CloudTrail is not actively logging.",
                    "DORA_Mapping": "Article 10 (Incident Reporting & Security Governance)",
                    "Severity": "Critical"
                })
        except ClientError:
            pass
        
        # Check if log file validation is enabled
        if not trail.get('LogFileValidationEnabled', False):
            trail_issue["Issues"].append({
                "Issue": "CloudTrail log file validation is not enabled.",
                "DORA_Mapping": "Article 10 (Incident Reporting & Security Governance)",
                "Severity": "Medium"
            })
        
        # Check if multi-region trail
        if not trail.get('IsMultiRegionTrail', False):
            trail_issue["Issues"].append({
                "Issue": "CloudTrail is not configured as a multi-region trail.",
                "DORA_Mapping": "Article 10 (Incident Reporting & Security Governance)",
                "Severity": "Medium"
            })
        
        if trail_issue["Issues"]:
            issues.append(trail_issue)
    
    return issues

def main():
    all_results = {}
    
    for region in REGIONS:
        region = region.strip()
        print(f"\n--- Scanning Region: {region} ---", file=sys.stderr)
        
        clients = get_clients(region)
        
        results = {
            "S3_Compliance_Issues": check_s3_compliance(clients['s3']),
            "EC2_SG_Issues": check_ec2_security_groups(clients['ec2']),
            "IAM_Issues": check_iam_policies() if region == REGIONS[0].strip() else [],  # IAM is global, check only once
            "VPC_Issues": check_vpc_configurations(clients['ec2']),
            "RDS_Issues": check_rds_compliance(clients['rds']),
            "CloudTrail_Issues": check_cloudtrail_compliance(clients['cloudtrail'])
        }
        
        all_results[region] = results
    
    # Calculate summary stats
    summary = calculate_summary(all_results)
    output = {
        "scan_timestamp": datetime.now().isoformat(),
        "regions_scanned": REGIONS,
        "summary": summary,
        "results": all_results
    }
    
    # Print results as JSON for consumption by other scripts
    print(json.dumps(output, indent=4))
    
    # Save to history file
    save_scan_history(output)

def calculate_summary(all_results):
    """Calculate summary statistics across all regions"""
    summary = {
        "total_issues": 0,
        "by_severity": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0},
        "by_category": {}
    }
    
    for region, results in all_results.items():
        for category, items in results.items():
            if category not in summary["by_category"]:
                summary["by_category"][category] = 0
            
            for item in items:
                for issue in item.get("Issues", []):
                    summary["total_issues"] += 1
                    severity = issue.get("Severity", "Low")
                    summary["by_severity"][severity] = summary["by_severity"].get(severity, 0) + 1
                    summary["by_category"][category] += 1
    
    return summary

def save_scan_history(scan_data):
    """Save scan results to history file"""
    history_dir = os.path.join(os.path.dirname(__file__), "scan_history")
    os.makedirs(history_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    history_file = os.path.join(history_dir, f"scan_{timestamp}.json")
    
    try:
        with open(history_file, 'w') as f:
            json.dump(scan_data, f, indent=4)
        print(f"Scan history saved to: {history_file}", file=sys.stderr)
    except Exception as e:
        print(f"Error saving scan history: {e}", file=sys.stderr)

if __name__ == '__main__':
    import sys
    main()