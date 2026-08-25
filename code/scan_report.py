# Performs the complete AWS security scan, generates the audit report, and sends it through SNS
import json
import boto3
import csv
import io
from datetime import datetime, timezone


# ============================================================
# AWS CLIENTS
# ============================================================

s3 = boto3.client("s3")
iam = boto3.client("iam")
ec2 = boto3.client("ec2")
rds = boto3.client("rds")
sns = boto3.client("sns")


# ============================================================
# SNS CONFIGURATION
# ============================================================

SNS_TOPIC_ARN = "arn:aws:sns:eu-north-1:308916794184:p2-security-alerts"


# ============================================================
# MAIN LAMBDA FUNCTION
# ============================================================

def lambda_handler(event, context):

    # Each finding will be stored as:
    # severity + service + resource + message

    findings = []


    # ========================================================
    # S3 SECURITY CHECK
    # ========================================================

    print("\n========== S3 SECURITY CHECK ==========")

    buckets = s3.list_buckets()

    for bucket in buckets["Buckets"]:

        bucket_name = bucket["Name"]

        print(f"Checking bucket: {bucket_name}")

        try:

            response = s3.get_public_access_block(
                Bucket=bucket_name
            )

            config = response["PublicAccessBlockConfiguration"]

            if (
                config["BlockPublicAcls"]
                and config["IgnorePublicAcls"]
                and config["BlockPublicPolicy"]
                and config["RestrictPublicBuckets"]
            ):

                print("✅ Public access protection enabled.")

                findings.append({
                    "severity": "PASS",
                    "service": "S3",
                    "resource": bucket_name,
                    "message": "Public access protection is enabled."
                })

            else:

                print("🚨 Public access protection is NOT fully enabled.")

                findings.append({
                    "severity": "HIGH",
                    "service": "S3",
                    "resource": bucket_name,
                    "message": "Public access protection is not fully enabled."
                })

        except Exception as e:

            print(f"⚠️ Could not retrieve settings: {e}")

            findings.append({
                "severity": "WARNING",
                "service": "S3",
                "resource": bucket_name,
                "message": "Could not retrieve public access settings."
            })


    # ========================================================
    # IAM USER MFA CHECK
    # ========================================================

    print("\n========== IAM MFA CHECK ==========")

    users = iam.list_users()

    for user in users["Users"]:

        username = user["UserName"]

        mfa = iam.list_mfa_devices(
            UserName=username
        )

        if len(mfa["MFADevices"]) > 0:

            print(f"✅ {username} - MFA enabled.")

            findings.append({
                "severity": "PASS",
                "service": "IAM",
                "resource": username,
                "message": "MFA is enabled."
            })

        else:

            print(f"🚨 {username} - MFA NOT enabled.")

            findings.append({
                "severity": "HIGH",
                "service": "IAM",
                "resource": username,
                "message": "MFA is not enabled."
            })


    # ========================================================
    # ROOT ACCOUNT MFA CHECK
    # ========================================================

    print("\n========== ROOT ACCOUNT MFA CHECK ==========")

    try:

        iam.generate_credential_report()

    except Exception as e:

        print(f"Note: {e}")


    report = iam.get_credential_report()

    csv_data = report["Content"].decode("utf-8")

    reader = csv.DictReader(
        io.StringIO(csv_data)
    )


    for row in reader:

        if row["user"] == "<root_account>":

            if row["mfa_active"] == "true":

                print("✅ Root Account MFA enabled.")

                findings.append({
                    "severity": "PASS",
                    "service": "ROOT ACCOUNT",
                    "resource": "Root Account",
                    "message": "MFA is enabled."
                })

            else:

                print("🚨 Root Account MFA NOT enabled.")

                findings.append({
                    "severity": "CRITICAL",
                    "service": "ROOT ACCOUNT",
                    "resource": "Root Account",
                    "message": "MFA is not enabled."
                })


    # ========================================================
    # SECURITY GROUP AUDIT
    # ========================================================

    print("\n========== SECURITY GROUP AUDIT ==========")

    response = ec2.describe_security_groups()

    security_groups = response["SecurityGroups"]


    for sg in security_groups:

        sg_id = sg["GroupId"]
        sg_name = sg["GroupName"]

        print(
            f"Checking Security Group: "
            f"{sg_name} ({sg_id})"
        )


        for rule in sg["IpPermissions"]:

            protocol = rule["IpProtocol"]

            from_port = rule.get("FromPort")

            to_port = rule.get("ToPort")


            for ip_range in rule.get("IpRanges", []):

                cidr = ip_range["CidrIp"]

                print(
                    f"Rule: {protocol} "
                    f"{from_port}-{to_port} "
                    f"Source: {cidr}"
                )


                # ------------------------------------------------
                # SSH OPEN TO INTERNET
                # ------------------------------------------------

                if (
                    cidr == "0.0.0.0/0"
                    and from_port == 22
                ):

                    print(
                        "🚨 HIGH RISK: "
                        "SSH open to the internet."
                    )

                    findings.append({
                        "severity": "HIGH",
                        "service": "SECURITY GROUP",
                        "resource": sg_name,
                        "message": (
                            "SSH (port 22) is open "
                            "to the internet."
                        )
                    })


                # ------------------------------------------------
                # ALL TRAFFIC OPEN TO INTERNET
                # ------------------------------------------------

                if (
                    cidr == "0.0.0.0/0"
                    and protocol == "-1"
                ):

                    print(
                        "🚨 CRITICAL: "
                        "All traffic open to the internet."
                    )

                    findings.append({
                        "severity": "CRITICAL",
                        "service": "SECURITY GROUP",
                        "resource": sg_name,
                        "message": (
                            "All traffic is allowed "
                            "from the internet."
                        )
                    })


    # ========================================================
    # RDS PUBLIC ACCESS CHECK
    # ========================================================

    print("\n========== RDS PUBLIC ACCESS CHECK ==========")

    response = rds.describe_db_instances()


    if not response["DBInstances"]:

        print("ℹ️ No RDS instances found.")

        findings.append({
            "severity": "INFO",
            "service": "RDS",
            "resource": "AWS Region",
            "message": "No RDS instances found in this region."
        })


    else:

        for db in response["DBInstances"]:

            db_identifier = db["DBInstanceIdentifier"]

            publicly_accessible = db["PubliclyAccessible"]


            if publicly_accessible:

                print(
                    f"🚨 {db_identifier} "
                    f"is publicly accessible."
                )

                findings.append({
                    "severity": "HIGH",
                    "service": "RDS",
                    "resource": db_identifier,
                    "message": "RDS instance is publicly accessible."
                })

            else:

                print(
                    f"✅ {db_identifier} "
                    f"is not publicly accessible."
                )

                findings.append({
                    "severity": "PASS",
                    "service": "RDS",
                    "resource": db_identifier,
                    "message": "RDS instance is not publicly accessible."
                })


    # ========================================================
    # COUNT FINDINGS
    # ========================================================

    critical = [
        finding for finding in findings
        if finding["severity"] == "CRITICAL"
    ]

    high = [
        finding for finding in findings
        if finding["severity"] == "HIGH"
    ]

    warnings = [
        finding for finding in findings
        if finding["severity"] == "WARNING"
    ]

    passed = [
        finding for finding in findings
        if finding["severity"] == "PASS"
    ]

    info = [
        finding for finding in findings
        if finding["severity"] == "INFO"
    ]


    # ========================================================
    # SCAN INFORMATION
    # ========================================================

    scan_time = datetime.now(
        timezone.utc
    ).strftime(
        "%d %b %Y, %H:%M UTC"
    )


    # ========================================================
    # BUILD PROFESSIONAL REPORT
    # ========================================================

    report = []


    # --------------------------------------------------------
    # HEADER
    # --------------------------------------------------------

    report.append(
        "AWS SECURITY AUDIT"
    )

    report.append(
        "=========================================="
    )

    report.append("")


    # --------------------------------------------------------
    # SCAN SUMMARY
    # --------------------------------------------------------

    report.append(
        "SCAN SUMMARY"
    )

    report.append(
        "------------------------------------------"
    )

    report.append(
        f"Region          : Stockholm (eu-north-1)"
    )

    report.append(
        f"Scan Time       : {scan_time}"
    )

    report.append(
        "Scanner         : AWS Security Scanner"
    )

    report.append(
        "Resources       : S3, IAM, EC2, RDS"
    )

    report.append("")


    # --------------------------------------------------------
    # RESULT SUMMARY
    # --------------------------------------------------------

    report.append(
        "RESULT SUMMARY"
    )

    report.append(
        "------------------------------------------"
    )

    report.append(
        f"🔴 Critical     : {len(critical)}"
    )

    report.append(
        f"🟠 High Risk    : {len(high)}"
    )

    report.append(
        f"🟡 Warnings     : {len(warnings)}"
    )

    report.append(
        f"🟢 Passed       : {len(passed)}"
    )

    report.append(
        f"🔵 Informational: {len(info)}"
    )

    report.append("")


    # ========================================================
    # FUNCTION TO ADD FINDINGS
    # ========================================================

    def add_section(
        title,
        emoji,
        section_findings
    ):

        if not section_findings:
            return

        report.append(title)

        report.append(
            "------------------------------------------"
        )

        for finding in section_findings:

            report.append(
                f"{emoji} {finding['service']}"
            )

            report.append(
                f"   Resource : {finding['resource']}"
            )

            report.append(
                f"   Finding  : {finding['message']}"
            )

            report.append("")


    # --------------------------------------------------------
    # CRITICAL FINDINGS
    # --------------------------------------------------------

    add_section(
        "CRITICAL FINDINGS",
        "🔴",
        critical
    )


    # --------------------------------------------------------
    # HIGH-RISK FINDINGS
    # --------------------------------------------------------

    add_section(
        "HIGH-RISK FINDINGS",
        "🟠",
        high
    )


    # --------------------------------------------------------
    # WARNINGS
    # --------------------------------------------------------

    add_section(
        "WARNINGS",
        "🟡",
        warnings
    )


    # --------------------------------------------------------
    # PASSED CHECKS
    # --------------------------------------------------------

    add_section(
        "PASSED CHECKS",
        "🟢",
        passed
    )


    # --------------------------------------------------------
    # INFORMATION
    # --------------------------------------------------------

    add_section(
        "INFORMATION",
        "🔵",
        info
    )


    # ========================================================
    # RECOMMENDATIONS
    # ========================================================

    report.append(
        "RECOMMENDED ACTIONS"
    )

    report.append(
        "------------------------------------------"
    )

    report.append(
        "1. Enable MFA for IAM users without MFA."
    )

    report.append(
        "2. Restrict SSH access to trusted IP ranges."
    )

    report.append(
        "3. Remove unrestricted security-group rules."
    )

    report.append(
        "4. Review unused or unnecessary security groups."
    )

    report.append(
        "5. Review RDS public accessibility when databases are deployed."
    )

    report.append("")


    # ========================================================
    # FOOTER
    # ========================================================

    report.append(
        "SCAN COMPLETE"
    )

    report.append(
        "------------------------------------------"
    )

    report.append(
        "AWS Security Scanner"
    )

    report.append(
        "Automated AWS security configuration audit."
    )


    # Convert list into one email message

    report_message = "\n".join(report)


    # ========================================================
    # PRINT REPORT TO CLOUDWATCH
    # ========================================================

    print("\n========== FINAL SECURITY REPORT ==========")

    print(report_message)


    # ========================================================
    # SEND REPORT THROUGH SNS
    # ========================================================

    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject="AWS Security Audit Report",
        Message=report_message
    )


    print(
        "\n✅ Security report sent through SNS."
    )


    # ========================================================
    # LAMBDA RESPONSE
    # ========================================================

    return {
        "statusCode": 200,
        "body": json.dumps(
            "AWS security audit completed and report sent."
        )
    }



