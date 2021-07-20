#! /usr/bin/env python
# -*- coding: utf-8 -*-

# Upside Travel, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import json
import sys

import boto3

from common import AV_STATUS_METADATA, LAMBDA_ENDPOINT
from common import AV_TIMESTAMP_METADATA
from common import S3_ENDPOINT


# Scan all objects in an S3 bucket that have not been previously scanned
def scan_objects(s3_client, s3_bucket_name, lambda_client, lambda_function_name, force_scan):
    s3_list_objects_result = {"IsTruncated": True}
    while s3_list_objects_result["IsTruncated"]:
        s3_list_objects_config = {"Bucket": s3_bucket_name}
        continuation_token = s3_list_objects_result.get("NextContinuationToken")
        if continuation_token:
            s3_list_objects_config["ContinuationToken"] = continuation_token
        s3_list_objects_result = s3_client.list_objects_v2(**s3_list_objects_config)
        print("Got pagination results")
        if "Contents" not in s3_list_objects_result:
            break
        for key in s3_list_objects_result["Contents"]:
            key_name = key["Key"]
            # Don't include objects that have been scanned
            if not object_previously_scanned(s3_client, s3_bucket_name, key_name, force_scan):
                scan_object(lambda_client, lambda_function_name, s3_bucket_name, key_name)
            else:
                try:
                    print("Skipping previously scanned object: {}".format(key_name).encode('utf-8'))
                except Exception:
                    print("Skipping previously scanned file name exception")


# Determine if an object has been previously scanned for viruses
def object_previously_scanned(s3_client, s3_bucket_name, key_name, force_scan):
    if force_scan:
        return False

    s3_object_tags = s3_client.get_object_tagging(Bucket=s3_bucket_name, Key=key_name)
    if "TagSet" not in s3_object_tags:
        return False
    for tag in s3_object_tags["TagSet"]:
        if tag["Key"] in [AV_STATUS_METADATA, AV_TIMESTAMP_METADATA]:
            return True
    return False


# Scan an S3 object for viruses by invoking the lambda function
# Skip any objects that have already been scanned
def scan_object(lambda_client, lambda_function_name, s3_bucket_name, key_name):

    try:
        print("Scanning: {}/{}".format(s3_bucket_name, key_name).encode('utf-8'))
    except Exception:
        print("Scanning: file name exception")

    s3_event = format_s3_event(s3_bucket_name, key_name)
    lambda_invoke_result = lambda_client.invoke(
        FunctionName=lambda_function_name,
        InvocationType="Event",
        Payload=json.dumps(s3_event),
    )
    if lambda_invoke_result["ResponseMetadata"]["HTTPStatusCode"] != 202:
        print("Error invoking lambda: {}".format(lambda_invoke_result).encode('utf-8'))


# Format an S3 Event to use when invoking the lambda function
# https://docs.aws.amazon.com/AmazonS3/latest/dev/notification-content-structure.html
def format_s3_event(s3_bucket_name, key_name):
    s3_event = {
        "Records": [
            {"s3": {"bucket": {"name": s3_bucket_name}, "object": {"key": key_name}}}
        ]
    }
    return s3_event


def str2bool(v):
    if isinstance(v, bool):
        return v
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')


def main(lambda_function_name, s3_bucket_name, force_scan):
    # Verify the lambda exists
    lambda_client = boto3.client("lambda", endpoint_url=LAMBDA_ENDPOINT)
    try:
        lambda_client.get_function(FunctionName=lambda_function_name)
        print("Lambda function {} exists".format(lambda_function_name).encode('utf-8'))
    except Exception:
        print("Lambda Function '{}' does not exist".format(lambda_function_name).encode('utf-8'))
        sys.exit(1)

    # Verify the S3 bucket exists
    s3_client = boto3.client("s3", endpoint_url=S3_ENDPOINT)
    try:
        s3_client.head_bucket(Bucket=s3_bucket_name)
        print("S3 bucket {} exists".format(s3_bucket_name).encode('utf-8'))
    except Exception:
        print("S3 Bucket '{}' does not exist".format(s3_bucket_name).encode('utf-8'))
        sys.exit(1)

    # Scan the objects in the bucket
    scan_objects(s3_client, s3_bucket_name, lambda_client, lambda_function_name, force_scan)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan an S3 bucket for viruses.")
    parser.add_argument(
        "--lambda-function-name",
        required=True,
        help="The name of the lambda function to invoke",
    )
    parser.add_argument(
        "--s3-bucket-name", required=True, help="The name of the S3 bucket to scan"
    )
    parser.add_argument("--force-scan", type=str2bool, nargs='?', const=True, default=False, help="Skip checking for previous scan results, which speeds things up")
    args = parser.parse_args()

    main(args.lambda_function_name, args.s3_bucket_name, args.force_scan)
