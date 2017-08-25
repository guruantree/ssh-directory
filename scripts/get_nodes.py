import boto3
import sys

region = None
asgname = None
label = None
elb_dnsname = None

if len(sys.argv) == 4:
    region = sys.argv[1]
    asgname = sys.argv[2]
    label = sys.argv[3]

elif len(sys.argv) == 5:
    region = sys.argv[1]
    asgname = sys.argv[2]
    label = sys.argv[3]
    elb_dnsname = sys.argv[4]

    #print ("Tag: " + label)
    #print ("Region : " + region)
    #print ("AutoScalingGroup: " + asgname)
else:
    print("Must provide: <region> <asgname> <label>")
    sys.exit()


def get_asg_nodes(asgname, region):
    client = boto3.client('autoscaling', region_name=region)
    nodes = []
    combined_list = []
    asginfo = client.describe_auto_scaling_instances()

    for node in asginfo['AutoScalingInstances']:
        if node['AutoScalingGroupName'] == asgname:
            nodes.append(node['InstanceId'])
    return nodes


def get_ip_address(instanceid, region, label):
    nodes = []
    client = boto3.client('ec2', region_name=region)
    response = client.describe_instances()


def get_ip_address(instanceid, region, label):
    nodes = []
    client = boto3.client('ec2', region_name=region)
    response = client.describe_instances()

    for r in response['Reservations']:
        for i in r['Instances']:
            if i['InstanceId'] == instanceid:
                if label == 'masters':
                    for n in i['NetworkInterfaces']:
                        if elb_dnsname:
                            hostdef = "{} {} {}".format(
                                n['PrivateIpAddress'].ljust(15),
                                ("openshift_ip=" + n['PrivateIpAddress']).ljust(25),
                                ("openshift_public_hostname=" + elb_dnsname)
                                )
                        else:
                            hostdef = "{} {} {}".format(n['PrivateIpAddress'].ljust(15),
                                                        ("openshift_public_ip=" + n['Association']['PublicIp']).ljust(25),
                                                        ("openshift_public_hostname=" + n['Association']['PublicIp'])
                                                        )
                    nodes.append(hostdef)
                else:
                    for n in i['NetworkInterfaces']:
                        hostdef = "{} {} {}".format(n['PrivateIpAddress'].ljust(15),
                                                    ("openshift_ip=" + n['PrivateIpAddress']).ljust(25),
                                                    ("openshift_hostname=" + n['PrivateIpAddress'])
                                                    )
                    nodes.append(hostdef)
    return nodes

if __name__ == '__main__':
    nodeids = get_asg_nodes(asgname, region)
    print("[{}]".format(label))
    for node in nodeids:
        n = get_ip_address(node, region, label)
        for host_record in n:
            print(host_record)
