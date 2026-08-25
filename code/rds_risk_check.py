#rds security check 
import json
import boto3
import csv
import io

s3 = boto3.client("s3")
iam = boto3.client("iam")
ec2 = boto3.client("ec2")
rds = boto3.client("rds")


def lambda_handler(event, context):

    print("========== S3 SECURITY CHECK ==========")

    buckets = s3.list_buckets()

    for bucket in buckets["Buckets"]:

        bucket_name = bucket["Name"]

        print(f"\nChecking bucket: {bucket_name}")

        try:
            response = s3.get_public_access_block(
                Bucket=bucket_name
            )

            config = response["PublicAccessBlockConfiguration"]

            if (
                config["BlockPublicAcls"] and
                config["IgnorePublicAcls"] and
                config["BlockPublicPolicy"] and
                config["RestrictPublicBuckets"]
            ):
                print("✅ Bucket is protected from public access.")
            else:
                print("🚨 WARNING: Public access protection is disabled!")

        except Exception as e:
            print(f"Could not retrieve settings: {e}")


    print("\n========== IAM MFA CHECK ==========")

    users = iam.list_users()

    for user in users["Users"]:

        username = user["UserName"]

        mfa = iam.list_mfa_devices(
            UserName=username
        )

        if len(mfa["MFADevices"]) > 0:
            print(f"✅ {username} - MFA Enabled")
        else:
            print(f"🚨 {username} - MFA NOT Enabled")


    print("\n========== ROOT ACCOUNT MFA CHECK ==========")

    try:
        iam.generate_credential_report()
    except Exception as e:
        print(f"Note on credential report generation: {e}")

    report = iam.get_credential_report()

    print("Credential report generated successfully.")

    csv_data = report["Content"].decode("utf-8")

    reader = csv.DictReader(
        io.StringIO(csv_data)
    )

    for row in reader:

        if row["user"] == "<root_account>":

            if row["mfa_active"] == "true":
                print("✅ Root Account MFA Enabled")
            else:
                print("🚨 CRITICAL: Root Account MFA NOT Enabled")


    print("\n========== SECURITY GROUP AUDIT ==========")

    response = ec2.describe_security_groups()

    security_groups = response["SecurityGroups"]

    for sg in security_groups:

        sg_id = sg["GroupId"]
        sg_name = sg["GroupName"]

        print(
            f"\nChecking Security Group: "
            f"{sg_name} ({sg_id})"
        )

        for rule in sg["IpPermissions"]:

            protocol = rule["IpProtocol"]

            from_port = rule.get("FromPort")
            to_port = rule.get("ToPort")

            print(
                f"Rule: Protocol={protocol}, "
                f"FromPort={from_port}, "
                f"ToPort={to_port}"
            )

            for ip_range in rule.get("IpRanges", []):

                cidr = ip_range["CidrIp"]

                print(f"    Source IPv4: {cidr}")

                if cidr == "0.0.0.0/0" and from_port == 22:
                    print(
                        "    🚨 HIGH RISK: "
                        "SSH (port 22) is open to the internet."
                    )

                if cidr == "0.0.0.0/0" and protocol == "-1":
                    print(
                        "    🚨 CRITICAL: "
                        "All traffic is open to the internet."
                    )


    print("\n========== RDS PUBLIC ACCESS CHECK ==========")

    response = rds.describe_db_instances()

    if not response["DBInstances"]:

        print("ℹ️ No RDS instances found in this region.")

    else:

        for db in response["DBInstances"]:

            db_identifier = db["DBInstanceIdentifier"]
            publicly_accessible = db["PubliclyAccessible"]

            print(
                f"\nChecking RDS Instance: "
                f"{db_identifier}"
            )

            if publicly_accessible:
                print(
                    "🚨 HIGH RISK: "
                    "RDS instance is publicly accessible."
                )
            else:
                print(
                    "✅ RDS instance is not publicly accessible."
                )


    return {
        "statusCode": 200,
        "body": json.dumps(
            "AWS security checks completed."
        )
    }
