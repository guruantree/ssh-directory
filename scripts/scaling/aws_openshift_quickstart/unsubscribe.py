#!/usr/bin/env python

import boto3
from subprocess import check_output
import requests
import json
import ast
import sys

class Unsubscribe(object):

    def getUUID(self, secret, argv):
        identity = requests.get('http://169.254.169.254/latest/dynamic/instance-identity/document').text
        region = json.loads(identity)['region']
        region_name = region.encode("UTF-8")

        autoscale = boto3.client('autoscaling',region_name)
        cf = boto3.client('cloudformation',region_name)
        stackResources = cf.describe_stack_resources(StackName=argv[1])
        stackres = stackResources["StackResources"]
        i = 0
        asgID = []
        instanceIds = []
        while i < len(stackres):
            if 'AWS::AutoScaling::AutoScalingGroup' in stackres[i]["ResourceType"]:
                print(stackres[i]["PhysicalResourceId"])
                asgID.append(stackres[i]["PhysicalResourceId"])
            i += 1
        print(asgID)    
        ec2 = boto3.resource('ec2',region_name)
        response = autoscale.describe_auto_scaling_instances()
        asg = response["AutoScalingInstances"]
        i = 0
        while i < len(asg):
            if asg[i]["AutoScalingGroupName"] in asgID:
                print(asg[i]["AutoScalingGroupName"])
                instanceIds.append(asg[i]["InstanceId"])
            i += 1
        print(instanceIds)        

        url ="wget -q -O - http://169.254.169.254/latest/meta-data/instance-id"
        ansibleServer = check_output(url,shell=True)
        instanceIds.append(ansibleServer)
        print(instanceIds)
        i = 0
        while i < len(instanceIds):
            local_instance = ec2.Instance(instanceIds[i])
            j = 0
            while j < len(local_instance.tags):
                if 'UUID' in local_instance.tags[j]['Key']:
                    print(local_instance)
                    print("{Key:"+local_instance.tags[j]['Key']+ " Value: "+local_instance.tags[j]['Value']+" }")
                    unsubscribe_url = 'https://subscription.rhn.redhat.com/subscription/consumers/' + local_instance.tags[j]['Value']
                    response = requests.delete(unsubscribe_url, verify='/etc/rhsm/ca/redhat-uep.pem', auth=(secret['user'],secret['password']))
                    print(response)
                j += 1
            i += 1
    #endDef

    def getSecret(self, argv):
        identity = requests.get('http://169.254.169.254/latest/dynamic/instance-identity/document').text
        region = json.loads(identity)['region']
        region_name = region.encode("UTF-8")
        cf = boto3.client('cloudformation', region_name)
        stack_name = argv[1]
        secret_id = cf.describe_stack_resource(StackName=stack_name, LogicalResourceId='RedhatSubscriptionSecret')['StackResourceDetail']['PhysicalResourceId']
        secrets = boto3.client('secretsmanager', region_name)
        secret_value = secrets.get_secret_value(SecretId=secret_id)['SecretString']
        return {'user': ast.literal_eval(secret_value)['user'], 'password': ast.literal_eval(secret_value)['password']}
    #endDef    

if __name__ == '__main__':
    mainInstance = Unsubscribe()
    auth = mainInstance.getSecret(sys.argv)
    mainInstance.getUUID(auth, sys.argv)
    