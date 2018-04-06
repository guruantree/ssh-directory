#Attach to Subscription pool
REDHAT_USERNAME=$1
REDHAT_PASSWORD=$2
REDHAT_POOLID=$3

yum clean all
rm -rf /var/cache/yum


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
    --enable="rhel-7-server-ose-3.9-rpms" \
    --enable="rhel-7-fast-datapath-rpms" \
    --enable="rhel-7-server-ansible-2.4-rpms"
