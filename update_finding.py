from dataclasses import dataclass

import boto3
from botocore.config import Config

# Retry up to 10 times as Inspector calls can get throttled - standard mode uses exponential backoff
config = Config(retries={"max_attempts": 10, "mode": "standard"})
inspector = boto3.client("inspector2", config=config)
securityhub = boto3.client("securityhub", config=config)


def dot_lookup(data, key, default=None):
    """Helper to get nested fields from dictionaries.
    
    For example, the dictionary:

    .. ::
        {
            "one": {
                "two": {
                    "three": 1
                }
            }
        }
    
    can be accessed as follows:

    .. ::
        >> dot_lookup(data, "one.two.three")
        ... 1
        >> dot_lookup(data, "one.two.four")
        ... None
        >> dot_lookup(data, "one.two.four", "N/A")
        ... N/A

    :param data: The dictionary to access
    :param key: A dot-attribute formatted string to look up
    :param default: The default value to return if nothing is found
    """
    for item in key.split("."):
        data = data.get(item, {})
    return data if data else default


@dataclass
class Arns:
    inspector_arn: str
    securityhub_arn: str
    product_arn: str


def lambda_handler(event, context):
    # Parse out necessary ARNs for lookups and updates:
    print("Input: ", event)
    arns = [
        Arns(
            inspector_arn=finding["Id"],
            securityhub_arn=dot_lookup(
                finding, "ProductFields.aws/securityhub/FindingId"
            ),
            product_arn=finding["ProductArn"],
        )
        for finding in dot_lookup(event, "detail.findings", [])
    ]
    if not arns:
        print("No valid Inspector ARNs found")
        return

    # Get the latest detailed CISA data from Inspector
    response = inspector.batch_get_finding_details(
        findingArns=[i.inspector_arn for i in arns]
    )
    if response.get("errors"):
        print(f"ERROR: Invalid inspector response: {response}")
        return

    for arn, finding in zip(arns, response["findingDetails"]):
        # Prevent an infinite loop in Lambda to see if our current Security Hub finding already has a
        # user defined field with this content.
        # The update of the UserDefinedFields causes an EventBridge event, so we want to rule out the
        # possibility that what we're doing is redundant
        current_finding = securityhub.get_findings(
            Filters={"Id": [{"Value": arn.inspector_arn, "Comparison": "EQUALS"}]}
        )
        fields = {
            "cisaDateAdded": dot_lookup(finding, "cisaData.dateAdded", ""),
            "ttps": ", ".join(dot_lookup(finding, "cisaData.dateAdded", "")),
        }
        if current_finding["Findings"][0].get("UserDefinedFields") == fields:
            print("Existing user defined fields match - not updating.")
            continue
        
        # Update the UserDefinedFields if they're net-new
        response = securityhub.batch_update_findings(
            FindingIdentifiers=[
                {"Id": arn.inspector_arn, "ProductArn": arn.product_arn}
            ],
            UserDefinedFields=fields,
        )
        if response.get("UnprocessedFindings") or not response.get("ProcessedFindings"):
            print(f"ERROR: Failed to update findings: {response}")
        else:
            print(f"Updated findings: {response}")
