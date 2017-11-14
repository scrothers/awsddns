import sys
import os
import json
import boto3
import time
from datetime import datetime

# Write logs to the Lambda logger.
def writeLog(logMsg = "", logChar = "+"):
    dateStamp = datetime.now().time().isoformat()
    print("[%s] (%s) %s" % (logChar, dateStamp, logMsg))

############################################
#    ____              __       ___________#
#   / __ \____  __  __/ /____  / ____/__  /#
#  / /_/ / __ \/ / / / __/ _ \/___ \  /_ < #
# / _, _/ /_/ / /_/ / /_/  __/___/ /___/ / #
#/_/ |_|\____/\__,_/\__/\___/_____//____/  #
#         Route53 Functions for DDNS       #
############################################

# Get the Route53 client we're going to need for this Lambda.
route53 = boto3.client('route53')

# Create a hostname record in Route53
def createRoute53Record(instanceId = ''):
    writeLog('Upserting records into Route53 for: i-%s' % instanceId, '+')
    record = dynamoGetHost(instanceId)
    response = route53.change_resource_record_sets(
        HostedZoneId = 'Z233B1GNRK5JDY',
        ChangeBatch = {
            'Changes': [
                {
                    'Action': 'UPSERT',
                    'ResourceRecordSet': {
                        'Name': "%s.intra.layerworx.net" % record['instanceId'],
                        'Type': 'A',
                        'TTL': 300,
                        'ResourceRecords': [
                            {
                                'Value': record['address']
                            }
                        ]
                    }
                },
                {
                    'Action': 'UPSERT',
                    'ResourceRecordSet': {
                        'Name': "%s.intra.layerworx.net" % record['hostName'],
                        'Type': 'A',
                        'TTL': 300,
                        'ResourceRecords': [
                            {
                                'Value': record['address']
                            }
                        ]
                    }
                }
            ]
        }
    )

# Delete a record in Route53
def deleteRoute53Record(instanceId = ''):
    writeLog('Deleting records into Route53 for: i-%s' % instanceId, '+')
    record = dynamoGetHost(instanceId)
    response = route53.change_resource_record_sets(
        HostedZoneId = 'Z233B1GNRK5JDY',
        ChangeBatch = {
            'Changes': [
                {
                    'Action': 'DELETE',
                    'ResourceRecordSet': {
                        'Name': "%s.intra.layerworx.net" % record['instanceId'],
                        'Type': 'A',
                        'TTL': 300,
                        'ResourceRecords': [
                            {
                                'Value': record['address']
                            }
                        ]
                    }
                },
                {
                    'Action': 'DELETE',
                    'ResourceRecordSet': {
                        'Name': "%s.intra.layerworx.net" % record['hostName'],
                        'Type': 'A',
                        'TTL': 300,
                        'ResourceRecords': [
                            {
                                'Value': record['address']
                            }
                        ]
                    }
                }
            ]
        }
    )


#########################################################
#    ____                                    ____  ____ #
#   / __ \__  ______  ____ _____ ___  ____  / __ \/ __ )#
#  / / / / / / / __ \/ __ `/ __ `__ \/ __ \/ / / / __  |#
# / /_/ / /_/ / / / / /_/ / / / / / / /_/ / /_/ / /_/ / #
#/_____/\__, /_/ /_/\__,_/_/ /_/ /_/\____/_____/_____/  #
#      /____/   DynamoDB Functions for DDNS             #
#########################################################

# Get all of the clients we're going to need for this Lambda.
dynamodb_client = boto3.client('dynamodb')
dynamodb_resource = boto3.resource('dynamodb')

# Check to make sure the DynamoDB table exists.
def dynamoTable():
    tableName = 'layerworx-ddns'
    return dynamodb_resource.Table(tableName)

# Create a record in DynamoDB for the instance.
def dynamoInsertHost(instanceId = '', hostName = '', address = ''):
    writeLog('Inserting instance into DynamoDB: i-%s' % instanceId, '+')
    dynamoTable().put_item(
        Item={
            'id': instanceId,
            'instanceId': 'i-%s' % instanceId,
            'hostName': hostName,
            'address': address,
        }
    )

# Get a record from DynamoDB for an instance.
def dynamoGetHost(instanceId = ''):
    writeLog('Retrieving instance from DynamoDB: i-%s' % instanceId, '*')
    return dynamoTable().get_item(
        Key={
            'id': instanceId
        }
    )['Item']

# Delete a record from DynamoDB for an instance.
def dynamoDeleteHost(instanceId = ''):
    writeLog('Deleting instance from DynamoDB: i-%s' % instanceId, '-')
    dynamoTable().delete_item(
        Key={
            'id': instanceId
        }
    )

##################################################################
#    _______________      ____           __                      #
#   / ____/ ____/__ \    /  _/___  _____/ /_____ _____  ________ #
#  / __/ / /    __/ /    / // __ \/ ___/ __/ __ `/ __ \/ ___/ _ \#
# / /___/ /___ / __/   _/ // / / (__  ) /_/ /_/ / / / / /__/  __/#
#/_____/\____//____/  /___/_/ /_/____/\__/\__,_/_/ /_/\___/\___/ #
#                                EC2 Functions for DDNS          #
##################################################################

# Get the EC2 clients.
ec2 = boto3.resource('ec2')
compute = boto3.client('ec2')

# Get instance information.
def getInstance(instanceId = ''):
    return compute.describe_instances(InstanceIds=[instanceId])

# Get the instance vpc from the api.
def getVpcId(instanceId = ''):
    return getInstance(instanceId)['Reservations'][0]['Instances'][0]['VpcId']

#############################################
#    __                    __        __     #
#   / /   ____ _____ ___  / /_  ____/ /___ _#
#  / /   / __ `/ __ `__ \/ __ \/ __  / __ `/#
# / /___/ /_/ / / / / / / /_/ / /_/ / /_/ / #
#/_____/\__,_/_/ /_/ /_/_.___/\__,_/\__,_/  #
#      Lambda Execution Function for DDNS   #
#############################################

def lambda_handler(event, context):
    writeLog('Lambda Invoked!', '!')
    instanceId = event['detail']['instance-id'].split('-')[1]
    instanceState = event['detail']['state']

    if instanceState == 'pending':
        writeLog('Pending state detected for instance: i-%s' % instanceId)
        instanceData = getInstance(event['detail']['instance-id'])
        dynamoInsertHost(
            instanceId = instanceId,
            address = instanceData['Reservations'][0]['Instances'][0]['PrivateIpAddress'],
            hostName = instanceData['Reservations'][0]['Instances'][0]['PrivateDnsName'].split('.')[0]
        )
        createRoute53Record(instanceId)

    elif instanceState == 'running':
        writeLog('Running state detected for instance: i-%s' % instanceId)
        instanceData = getInstance(event['detail']['instance-id'])
        dynamoInsertHost(
            instanceId = instanceId,
            address = instanceData['Reservations'][0]['Instances'][0]['PrivateIpAddress'],
            hostName = instanceData['Reservations'][0]['Instances'][0]['PrivateDnsName'].split('.')[0]
        )
        createRoute53Record(instanceId)

    elif instanceState == 'shutting-down':
        writeLog('Shutting down state detected for instance: i-%s' % instanceId)
        instanceData = getInstance(event['detail']['instance-id'])
        dynamoInsertHost(
            instanceId = instanceId,
            address = instanceData['Reservations'][0]['Instances'][0]['PrivateIpAddress'],
            hostName = instanceData['Reservations'][0]['Instances'][0]['PrivateDnsName'].split('.')[0]
        )
        createRoute53Record(instanceId)

    elif instanceState == 'stopped':
        writeLog('Stopped state detected for instance: i-%s' % instanceId)
        instanceData = getInstance(event['detail']['instance-id'])
        dynamoInsertHost(
            instanceId = instanceId,
            address = instanceData['Reservations'][0]['Instances'][0]['PrivateIpAddress'],
            hostName = instanceData['Reservations'][0]['Instances'][0]['PrivateDnsName'].split('.')[0]
        )
        createRoute53Record(instanceId)

    elif instanceState == 'stopping':
        writeLog('Stopping state detected for instance: i-%s' % instanceId)
        instanceData = getInstance(event['detail']['instance-id'])
        dynamoInsertHost(
            instanceId = instanceId,
            address = instanceData['Reservations'][0]['Instances'][0]['PrivateIpAddress'],
            hostName = instanceData['Reservations'][0]['Instances'][0]['PrivateDnsName'].split('.')[0]
        )
        createRoute53Record(instanceId)

    elif instanceState == 'terminated':
        writeLog('Terminated state detected for instance: i-%s' % instanceId, '-')
        deleteRoute53Record(instanceId)
        dynamoDeleteHost(
            instanceId = instanceId,
        )
