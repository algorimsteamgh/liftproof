#!/usr/bin/env bash
# Release gate for the OS layer (ATS-009): launch a throwaway instance from the new AMI,
# let Amazon Inspector scan it, and fail on any HIGH or CRITICAL finding that has a fix. The findings
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
  --tag-specifications "ResourceType=instance,Tags=[{Key=liftproof:build,Value=true},{Key=Name,Value=liftproof-ami-scan}]" \
    "ResourceType=volume,Tags=[{Key=liftproof:build,Value=true}]" \
  --query 'Instances[0].InstanceId' --output text)
trap 'aws ec2 terminate-instances --instance-ids "$iid" >/dev/null' EXIT
echo "scanning $ami on $iid"

# Wait for Inspector to finish its first scan of this instance. Coverage turns ACTIVE as
# soon as the instance is discovered, with reason PENDING_INITIAL_SCAN and no
# lastScannedAt; reading findings then would pass an image nothing has scanned. This is a
# release job in our own account, not the product: the product never polls a control
# plane API.
while :; do
  read -r status reason scanned < <(aws inspector2 list-coverage \
    --filter-criteria "resourceId=[{comparison=EQUALS,value=$iid}]" \
    --query 'coveredResources[0].[scanStatus.statusCode,scanStatus.reason,lastScannedAt]' \
    --output text 2>/dev/null || echo "None None None") || true
  echo "$(date -u +%H:%M:%S) coverage: ${status:-None} ${reason:-None} last scan ${scanned:-None}"
  if [ "$status" = "ACTIVE" ] && [ "$reason" != "PENDING_INITIAL_SCAN" ] \
    && [ -n "$scanned" ] && [ "$scanned" != "None" ]; then
    break
  fi
  [ "$(date +%s)" -gt "$deadline" ] && { echo "Inspector did not scan $iid in time (last: $status $reason)"; exit 2; }
  sleep 60
done
sleep 120 # findings from the scan are written shortly after lastScannedAt

aws inspector2 list-findings \
  --filter-criteria "resourceId=[{comparison=EQUALS,value=$iid}],findingStatus=[{comparison=EQUALS,value=ACTIVE}]" \
  --output json > scan-findings.json
# A HIGH or CRITICAL finding with a fix available blocks the release: the image is built
# from a fully upgraded base, so a fixable one means the build missed an update. One
# with no fix published yet (fixAvailable NO, common for Ubuntu kernel CVEs) cannot be
# removed by any build; it is listed here and kept in the evidence (decision 140).
high='.findings[] | select(.severity=="HIGH" or .severity=="CRITICAL")'
blocking=$(jq "[$high | select(.fixAvailable != \"NO\")] | length" scan-findings.json)
unfixed=$(jq "[$high | select(.fixAvailable == \"NO\")] | length" scan-findings.json)
jq -r '.findings[] | "\(.severity)\tfix \(.fixAvailable // "?")\t\(.title)"' scan-findings.json \
  | sort | uniq -c || true
if [ "$blocking" -gt 0 ]; then
  echo "BLOCKED: $blocking high or critical findings with a fix available on $ami"
  exit 1
fi
echo "no fixable high or critical findings on $ami ($unfixed with no fix published yet)"
