#!/bin/bash
#Attach to Subscription pool

yum clean all
rm -rf /var/cache/yum

CREDS=$(aws secretsmanager get-secret-value --secret-id ${1} --region ${AWS_REGION} --query SecretString --output text)
REDHAT_USERNAME=$(echo ${CREDS} | jq -r .user)
REDHAT_PASSWORD=$(echo ${CREDS} | jq -r .password)
REDHAT_POOLID=$(echo ${CREDS} | jq -r .poolid)

subscription-manager register --username=${REDHAT_USERNAME} --password=${REDHAT_PASSWORD} --force
if [ $? -ne 0 ]; then
	subscription-manager clean
	subscription-manager register --username=${REDHAT_USERNAME} --password=${REDHAT_PASSWORD} --force
fi

subscription-manager status
if [ $? -eq 0 ]; then
	exit 1
fi

subscription-manager attach --pool=${REDHAT_POOLID}
subscription-manager repos --enable="rhel-7-server-rpms" \
    --enable="rhel-7-server-extras-rpms" \
    --enable="rhel-7-server-ose-3.10-rpms" \
    --enable="rhel-7-fast-datapath-rpms" \
    --enable="rhel-7-server-ansible-2.4-rpms" \
    --enable="rh-gluster-3-client-for-rhel-7-server-rpms"

var=($(subscription-manager identity))
UUID="${var[2]}"
aws ec2 create-tags --resources $INSTANCE_ID --tags Key=UUID,Value=$UUID --region ${AWS_REGION}
