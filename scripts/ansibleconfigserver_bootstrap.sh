#!/bin/bash -x

source ${P}
echo "	------------------[] Starting: epel configuration via [qs_enable_epel]"
# Needed for initial Ansible availability
qs_enable_epel &> /var/log/userdata.qs_enable_epel.log || qs_err " enable epel failed "
echo "	------------------[] Completed epel configuration "

echo "========================================================================================================================"
echo "	------------------[] Completed: QuickStart Common Utils "

echo "[INFO] Configuring External LoadBalancer for OpenShift UI" 
aws autoscaling attach-load-balancers --auto-scaling-group-name ${OPENSHIFTMASTERASG} --load-balancer-names ${OPENSHIFTMASTERINTERNALELB} --region ${AWS_REGION}

echo "[INFO] Configuring External LoadBalancer for ContainerAccess UI" 
aws autoscaling attach-load-balancers --auto-scaling-group-name ${OPENSHIFTASG} --load-balancer-names ${CONTAINERACCESSELB} --region ${AWS_REGION}

echo "========================================================================================================================"
echo "	------------------[]Attach to Subscription pool"

aws s3 cp ${QS_S3URI}scripts/redhat_ose-register-${OCP_VERSION}.sh ~/redhat_ose-register.sh
chmod 755 ~/redhat_ose-register.sh
qs_retry_command 20 ~/redhat_ose-register.sh ${RH_USER} ${RH_PASS} ${RH_POOLID}

echo "========================================================================================================================"
echo "	------------------[] Check if Subscription is Attached! if not fail Stack"

echo " 	------------------[] Start of main execution block"
yum repolist | grep OpenShift 
if [[ $? == 0 ]]; then 
    echo "	------------------[] Starting OpenShift Configuration" 
    echo "[INFO] Generating Ansible inventory " 
    pip install boto3 &> /var/log/userdata.boto3_install.log || qs_err " boto3 install failed "
    mkdir -p /root/ose_scaling/aws_openshift_quickstart
    mkdir -p /root/ose_scaling/bin
    aws s3 cp ${QS_S3URI}scripts/scaling/aws_openshift_quickstart/__init__.py /root/ose_scaling/aws_openshift_quickstart/__init__.py
    aws s3 cp ${QS_S3URI}scripts/scaling/aws_openshift_quickstart/logger.py /root/ose_scaling/aws_openshift_quickstart/logger.py
    aws s3 cp ${QS_S3URI}scripts/scaling/aws_openshift_quickstart/scaler.py /root/ose_scaling/aws_openshift_quickstart/scaler.py
    aws s3 cp ${QS_S3URI}scripts/scaling/aws_openshift_quickstart/utils.py /root/ose_scaling/aws_openshift_quickstart/utils.py
    aws s3 cp ${QS_S3URI}scripts/scaling/bin/aws-ose-qs-scale /root/ose_scaling/bin/aws-ose-qs-scale
    aws s3 cp ${QS_S3URI}scripts/scaling/setup.py /root/ose_scaling/setup.py
    pip install /root/ose_scaling 
    # Start cfn-configset [cfg_node_keys]
    cfn-init -v --stack ${AWS_STACKNAME} --resource AnsibleConfigServer --configsets cfg_node_keys --region ${AWS_REGION} 

    # Start cfn-configset [cfg_ansible]
    cfn-init -v --stack ${AWS_STACKNAME} --resource AnsibleConfigServer --configsets cfg_ansible --region ${AWS_REGION} 

    echo "Begin OpenShift configuration"
    aws s3 cp ${QS_S3URI}scripts/openshift_config_ose.yml  ~/openshift_config.yml 
    cat ~/openshift_config.yml >/etc/ansible/hosts 
    echo "[INFO] Ansible Generated" 


    echo "[INFO] Configuring OpenShift Variable" 
    echo openshift_master_cluster_hostname=${INTERNAL_MASTER_ELBDNSNAME} >> /etc/ansible/hosts 
    echo openshift_master_cluster_public_hostname=${MASTER_ELBDNSNAME} >> /etc/ansible/hosts 
    echo openshift_master_default_subdomain=${MASTER_ELBDNSNAME} >> /etc/ansible/hosts 

    if [ "${ENABLE_HAWKULAR}" == "True" ] ; then
        echo openshift_metrics_hawkular_hostname=metrics.${MASTER_ELBDNSNAME} >> /etc/ansible/hosts 
        echo openshift_metrics_install_metrics=true >> /etc/ansible/hosts 
        echo openshift_metrics_start_cluster=true >> /etc/ansible/hosts 
        echo openshift_metrics_cassandra_storage_type=dynamic >> /etc/ansible/hosts 
    fi

    echo openshift_master_api_port=443 >> /etc/ansible/hosts 
    echo openshift_master_console_port=443 >> /etc/ansible/hosts
    if [ "${OCP_VERSION}" == "3.9" ]; then
        echo openshift_web_console_prefix=openshift3/ose- >> /etc/ansible/hosts
        echo openshift_web_console_version=v3.9 >> /etc/ansible/hosts
    fi
    echo "[INFO] Configured OpenShift Variable" 
    /bin/aws-ose-qs-scale --generate-initial-inventory --debug 
    cat /tmp/openshift_ansible_inventory* >> /etc/ansible/hosts 
    sed -i 's/#pipelining = False/pipelining = True/g' /etc/ansible/ansible.cfg 
    sed -i 's/#log_path/log_path/g' /etc/ansible/ansible.cfg 
    sed -i 's/#stdout_callback.*/stdout_callback = json/g' /etc/ansible/ansible.cfg 
    echo "[INFO] Poll till all nodes are under Ansible (max tries = 50)" 
    qs_retry_command 50 ansible -m ping all 

    #Install dependencies and update OS
    yum -y install wget git net-tools bind-utils iptables-services bridge-utils bash-completion kexec-tools sos psacct
    yum -y update 
    yum -y install atomic-openshift-utils
    yum -y install atomic-openshift-excluder atomic-openshift-docker-excluder
    yum install -y https://s3-us-west-1.amazonaws.com/amazon-ssm-us-west-1/latest/linux_amd64/amazon-ssm-agent.rpm 
    systemctl start amazon-ssm-agent 
    systemctl enable amazon-ssm-agent 
    CURRENT_PLAYBOOK_VERSION=https://github.com/openshift/openshift-ansible/archive/openshift-ansible-${OCP_ANSIBLE_RELEASE}.tar.gz
    curl  --retry 5  -Ls ${CURRENT_PLAYBOOK_VERSION} -o openshift-ansible.tar.gz 
    tar -zxf openshift-ansible.tar.gz 
    mkdir -p /usr/share/ansible 
    mv openshift-ansible-* /usr/share/ansible/openshift-ansible 

    yum -y install atomic-openshift-excluder atomic-openshift-docker-excluder
    atomic-openshift-excluder unexclude
    echo "[INFO] Starting OpenShift Cluster Build (Beginning Ansible Playbook run!!!)" 
    date >>~/playbooks.info
    date >>~/playbooks.info
    aws s3 cp ${QS_S3URI}scripts/scaleup_wrapper.yml  /usr/share/ansible/openshift-ansible/
    if [ "${OCP_VERSION}" == "3.7" ]; then
        ansible-playbook /usr/share/ansible/openshift-ansible/playbooks/byo/config.yml || qs_err " Openshift installation failed!! "
    elif [ "${OCP_VERSION}" == "3.9" ]; then
        ansible-playbook /usr/share/ansible/openshift-ansible/playbooks/prerequisites.yml || qs_err " Openshift prerequisite installation failed!! "
        ansible-playbook /usr/share/ansible/openshift-ansible/playbooks/deploy_cluster.yml || qs_err " Openshift installation failed!! "
    fi
    date >>~/playbooks.info
    echo "[INFO] Finished OpenShift Cluster Build (Completed Ansible Playbook run!!!)" 
    
    echo "[INFO] Adding OpenShift Users" 
    ansible masters -a "htpasswd -b /etc/origin/master/htpasswd admin ${OCP_PASS}" 
    echo "[INFO] Added OpenShift Users" 
    echo "[INFO] Refresh all services" 
    ansible all -a "systemctl restart dbus" 
    ansible all -a "systemctl restart dnsmasq" 
    ansible all -m wait_for -a "path=/var/run/dbus/system_bus_socket" 
    ansible all -a "systemctl restart atomic*" 
    ansible all -a "systemctl restart NetworkManager" 
    ansible all -a "systemctl restart systemd-logind" 
    AWSSB_SETUP_HOST=$(cat /etc/ansible/hosts | awk NF | grep -A1 '\[masters\]' | tail -n 1 | awk '{print $1}')
    lb_operational=0
    sleep=10
    while [ "$lb_operational" == "0" ]; do
        if [ $sleep -gt 60 ] ; then
            qs_err "Failed to get all API servers responding through the internal ELB"
            break
        fi
        lb_operational=1
        ssh $AWSSB_SETUP_HOST 'oc whoami' || lb_operational=0
        ssh $AWSSB_SETUP_HOST 'oc whoami' || lb_operational=0
        ssh $AWSSB_SETUP_HOST 'oc whoami' || lb_operational=0
        if [ "$lb_operational" == "0" ]; then
            for lb in $(aws elb describe-load-balancers --region ${AWS_REGION} --no-paginate --query 'LoadBalancerDescriptions[?Scheme==`internal`].[LoadBalancerName]' --output text) ; do 
                LB=$(aws elb describe-tags --load-balancer-names ${lb} --region ${AWS_REGION} --query 'TagDescriptions[? Tags[? Value==`${AWS_STACKID}` \
                   && Key==`aws:cloudformation:stack-id`] && Tags[? Value==`OpenShiftMasterInternalELB` && Key==`aws:cloudformation:logical-id`]].[LoadBalancerName]' --output text)
                if [ "$(echo $LB)" != "" ] ; then 
                    aws elb delete-load-balancer-listeners --load-balancer-name ${LB} --load-balancer-ports 443 --region ${AWS_REGION}
                    sleep $sleep
                    aws elb create-load-balancer-listeners --load-balancer-name ${LB} --listeners Protocol=tcp,LoadBalancerPort=443,InstanceProtocol=tcp,InstancePort=443 --region ${AWS_REGION}
                fi 
            done 
            sleep $sleep
            let "sleep+=5"
        fi
    done 
    echo "[INFO] Finished OpenShift Cluster Build" 
    if [ "${ENABLE_AWSSB}" == "Enabled" ]; then
        echo "[INFO] Installing the AWS Service Broker"
        ssh $AWSSB_SETUP_HOST "QS_S3URI=${QS_S3URI} \
            ; yum install -y wget \
            && mkdir -p ~/aws_broker_install \
            && cd ~/aws_broker_install \
            && wget https://s3.amazonaws.com/awsservicebroker/scripts/deploy-awsservicebroker.template.yaml \
            && wget https://s3.amazonaws.com/awsservicebroker/scripts/deploy_aws_broker.sh \
            && chmod +x deploy_aws_broker.sh \
            && ./deploy_aws_broker.sh \
            && aws s3 cp ${QS_S3URI}scripts/secrets.yaml ./secrets.yaml \
            && sed -i \"s~<CFN_ROLE_ARN>~${AWSSB_ROLE}~g\" ./secrets.yaml \
            && sed -i \"s/<REGION>/${AWS_REGION}/\" ./secrets.yaml \
            && sed -i \"s/<VPC_ID>/${VPCID}/\" ./secrets.yaml \
            && oc create -f ./secrets.yaml -n aws-service-broker \
            && oc get configmap broker-config -n aws-service-broker -o yaml > aws-sb-config.yaml \
            && sed -i \"s/^kind: ConfigMap$/    secrets:\\n&/\" aws-sb-config.yaml \
            && for apb in \$(echo 'dh-sqs-apb dh-sns-apb dh-r53-apb dh-rds-apb dh-emr-apb dh-redshift-apb dh-elasticache-apb dh-dynamodb-apb dh-s3-apb dh-athena-apb dh-kinesis-apb dh-kms-apb dh-lex-apb dh-polly-apb dh-rdsmariadb-apb dh-rdspostgresql-apb dh-rekognition-apb dh-translate-apb'); do \
                sed -i \"s/^kind: ConfigMap$/      - {apb_name: \${apb}, secret: aws-secret, title: aws-secret}\\n&/\" aws-sb-config.yaml \
            ; done \
            ; oc replace -f ./aws-sb-config.yaml -n aws-service-broker \
            && oc rollout status dc/aws-asb  -n aws-service-broker ; oc rollout latest aws-asb -n aws-service-broker" || qs_err " failed to setup the AWS Service Broker"
        echo "[INFO] Finished Installing the AWS Service Broker" 
    fi
    echo "[INFO] Signaling Stack ....."
    # Signal resource using [qs_status] via cfn-init
    cfn-signal -e $(qs_status) --stack ${AWS_STACKNAME} --resource AnsibleConfigServer --region ${AWS_REGION}
    
    echo "End cfn stack signaling"
    echo "	#################[] End of main execution block " 
else 
    echo " 	#################[] Start of else block "
    echo "[REASON] Failed to Acquire OpenShift Entitlement, Check your PoolID and RHN UserName/Password " >~/failure_reason
    echo "[INFO] Signaling Stack ....."
    cfn-signal -e 1 --stack ${AWS_STACKNAME} --resource AnsibleConfigServer --region ${AWS_REGION}
    echo " 	#################[] End of else block "
fi 