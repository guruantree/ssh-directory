#  Copyright 2016 Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
#  This file is licensed to you under the AWS Customer Agreement (the "License").
#  You may not use this file except in compliance with the License.
#  A copy of the License is located at http://aws.amazon.com/agreement/ .
#  This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express or implied.
#  See the License for the specific language governing permissions and limitations under the License.

import boto3
import cfnresponse
import json
import traceback



def lambda_handler(event, context):
    try:
        print(json.dumps(event))
        print(event['RequestType'])
        print('Getting AnsibleConfigServer instance...')
        print event["ResourceProperties"]["StackName"]
        print event["ResourceProperties"]["AnsibleConfigServer"]
        if event['RequestType'] == 'Delete':
            print("Run unsubscribe script")
            ssm = boto3.client('ssm')
            instanceID = event["ResourceProperties"]["AnsibleConfigServer"]
            response = ssm.send_command(Targets=[{"Key":"instanceids","Values":[instanceID]}],
                            DocumentName="AWS-RunShellScript",
                            Parameters={"commands":["python unsubscribe.py %s" %(event["ResourceProperties"]["StackName"])],
                                        "executionTimeout":["600"],
                                        "workingDirectory":["/root"]},
                            Comment="Execute script in ansible server to unsubscribe nodes from RH subscription",
                            TimeoutSeconds=120)
            print(response)                   
    except Exception as e:
        print(e)
        traceback.print_exc()
    cfnresponse.send(event, context, cfnresponse.SUCCESS, {}, '')
