# security-hub-user-field-update

A Lambda function to update UserDefinedFields for SecurityHub finding events from Inspector.
Inspector contains useful metadata that customers sometimes want to search on in SecurityHub. Today,
this information is not easily searchable. By adding custom UserDefinedFields to these findings, however,
we can add this search functionality to SecurityHub.

## Requirements

Assumes you have already created a Lambda layer for boto3 with the latest version, `1.28.21`, as this is
required for calling the Inspector `BatchGetFindingDetails` API.