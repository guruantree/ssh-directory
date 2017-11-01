#Attach to Subscription pool
REDHAT_USERNAME=$1
REDHAT_PASSWORD=$2
REDHAT_POOLID=$3

yum clean all
rm -rf /var/cache/yum

subscription-manager register --username=${REDHAT_USERNAME} --password=${REDHAT_PASSWORD} --force || subscription-manager clean && subscription-manager register --username=${REDHAT_USERNAME} --password=${REDHAT_PASSWORD} --force 
subscription-manager attach --pool=${REDHAT_POOLID}
subscription-manager repos --enable="rhel-7-server-ose-3.6-rpms" --enable="rhel-7-server-extras-rpms" --enable="rhel-7-fast-datapath-rpms"
