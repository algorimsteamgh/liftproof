#!/usr/bin/env bash
# Release gate for the OS layer (ATS-009): launch a throwaway instance from the new AMI,
# let Amazon Inspector scan it, and fail on any HIGH or CRITICAL finding. The findings
# are written to scan-findings.json for the evidence bucket either way.
#
# usage: scan-ami.sh AMI_ID SUBNET_ID SECURITY_GROUP_ID INSTANCE_PROFILE
set -euo pipefail
ami=$1 subnet=$2 sg=$3 profile=$4
deadline=$(( $(date +%s) + 3600 ))

iid=$(aws ec2 run-instances --image-id "$ami" --instance-type m7i.large \
  --subnet-id "$subnet" --security-group-ids "$sg" \
  --iam-instance-profile Name="$profile" \
  --metadata-options HttpTokens=required,HttpEndpoint=enabled \
  --tag-specifications "ResourceType=instance,Tags=[{Key=certus:build,Value=true},{Key=Name,Value=certus-ami-scan}]" \
    "ResourceType=volume,Tags=[{Key=certus:build,Value=true}]" \
  --query 'Instances[0].InstanceId' --output text)
trap 'aws ec2 terminate-instances --instance-ids "$iid" >/dev/null' EXIT
echo "scanning $ami on $iid"

# Wait for Inspector to report a completed scan of this instance. This is a release job
# in our own account, not the product: the product never polls a control plane API.
while :; do
  status=$(aws inspector2 list-coverage \
    --filter-criteria "resourceId=[{comparison=EQUALS,value=$iid}]" \
    --query 'coveredResources[0].scanStatus.statusCode' --output text 2>/dev/null || true)
  [ "$status" = "ACTIVE" ] && break
  [ "$(date +%s)" -gt "$deadline" ] && { echo "Inspector did not scan $iid in time"; exit 2; }
  sleep 60
done
sleep 300 # first findings land a few minutes after coverage turns active

aws inspector2 list-findings \
  --filter-criteria "resourceId=[{comparison=EQUALS,value=$iid}],findingStatus=[{comparison=EQUALS,value=ACTIVE}]" \
  --output json > scan-findings.json
blocking=$(jq '[.findings[] | select(.severity=="HIGH" or .severity=="CRITICAL")] | length' scan-findings.json)
jq -r '.findings[] | "\(.severity)\t\(.title)"' scan-findings.json | sort | uniq -c || true
if [ "$blocking" -gt 0 ]; then
  echo "BLOCKED: $blocking high or critical findings on $ami"
  exit 1
fi
echo "no high or critical findings on $ami"
