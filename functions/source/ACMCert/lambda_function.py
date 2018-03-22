import json
import logging
import boto3
import cfnresponse
import time
import re


acm_client = boto3.client('acm')
r53_client = boto3.client('route53')
lambda_client = boto3.client('lambda')


def handler(event, context):
    print('Received event: %s' % json.dumps(event))
    status = cfnresponse.SUCCESS
    physical_resource_id = None
    data = {}
    reason = None
    cfn_signal = True
    try:
        if event['RequestType'] == 'Create':
            token = ''.join(ch for ch in str(event['StackId'] + event['LogicalResourceId']) if ch.isalnum())
            token = token[len(token)-32:]
            arn = acm_client.request_certificate(ValidationMethod='DNS', DomainName=event['ResourceProperties']['HostNames'][0], SubjectAlternativeNames=event['ResourceProperties']['HostNames'][1:], IdempotencyToken=token)['CertificateArn']
            physical_resource_id = arn
            rs={}
            while True:
                try:
                    for d in acm_client.describe_certificate(CertificateArn=arn)['Certificate']['DomainValidationOptions']:
                        rs[d['ResourceRecord']['Name']] = d['ResourceRecord']['Value']
                    break
                except KeyError:
                    if (context.get_remaining_time_in_millis() / 1000.00) > 20.0:
                        print('waiting for ResourceRecord to be available')
                        time.sleep(15)
                    else:
                        logging.error('timed out waiting for ResourceRecord')
                        status = cfnresponse.FAILED
                    time.sleep(15)
            rs = [{'Action': 'CREATE', 'ResourceRecordSet': {'Name': r, 'Type': 'CNAME', 'TTL': 600,'ResourceRecords': [{'Value': rs[r]}]}} for r in rs.keys()]
            try:
                r53_client.change_resource_record_sets(HostedZoneId=event['ResourceProperties']['HostedZoneId'], ChangeBatch={'Changes': rs})
            except Exception as e:
                if not str(e).endswith('but it already exists'):
                    raise
            while 'PENDING_VALIDATION' in [v['ValidationStatus'] for v in acm_client.describe_certificate(CertificateArn=arn)['Certificate']['DomainValidationOptions']]:
                print('waiting for validation to complete')
                if (context.get_remaining_time_in_millis() / 1000.00) > 20.0:
                    time.sleep(15)
                else:
                    # lambda_client.invoke(FunctionName=context.function_name, InvocationType='Event', Payload=bytes(json.dumps(event)))
                    logging.error('validation timed out')
                    status = cfnresponse.FAILED
                    # cfn_signal=False
            for r in [v['ValidationStatus'] for v in acm_client.describe_certificate(CertificateArn=arn)['Certificate']['DomainValidationOptions']]:
                if r != 'SUCCESS':
                    status = cfnresponse.FAILED
                    reason = 'One or more domains failed to validate'
                    logging.error(reason)
            data['Arn'] = arn
        elif event['RequestType'] == 'Update':
            reason = 'Exception: Stack updates are not supported'
            logging.error(reason)
            status = cfnresponse.FAILED
            physical_resource_id = event['PhysicalResourceId']
        elif event['RequestType'] == 'Delete':
            physical_resource_id=event['PhysicalResourceId']
            if not re.match(r'arn:[\w+=/,.@-]+:[\w+=/,.@-]+:[\w+=/,.@-]*:[0-9]+:[\w+=,.@-]+(/[\w+=,.@-]+)*', physical_resource_id):
                print("PhysicalId is not an acm arn, assuming creation never happened and skipping delete")
            else:
                rs={}
                for d in acm_client.describe_certificate(CertificateArn=physical_resource_id)['Certificate']['DomainValidationOptions']:
                    rs[d['ResourceRecord']['Name']] = d['ResourceRecord']['Value']
                rs = [{'Action': 'DELETE', 'ResourceRecordSet': {'Name': r, 'Type': 'CNAME', 'TTL': 600,'ResourceRecords': [{'Value': rs[r]}]}} for r in rs.keys()]
                r53_client.change_resource_record_sets(HostedZoneId=event['ResourceProperties']['HostedZoneId'], ChangeBatch={'Changes': rs})
                time.sleep(10)
                acm_client.delete_certificate(CertificateArn=physical_resource_id)

    except Exception as e:
        logging.error('Exception: %s' % e, exc_info=True)
        reason = str(e)
        status = cfnresponse.FAILED
    finally:
        if cfn_signal:
            cfnresponse.send(event, context, status, data, physical_resource_id, reason)
