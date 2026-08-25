# Checks S3 public access protection
import json
import boto3

s3 = boto3.client("s3")

def lambda_handler(event, context):

    buckets = s3.list_buckets()

    for bucket in buckets["Buckets"]:

        bucket_name = bucket["Name"]

        print(f"\nChecking bucket: {bucket_name}")

        try:
            response = s3.get_public_access_block(
                Bucket=bucket_name
            )

            config = response["PublicAccessBlockConfiguration"]

            print("Public Access Block Settings:")

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

    return {
        "statusCode": 200,
        "body": json.dumps("S3 Public Access Block check completed.")
    }
