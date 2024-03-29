from botocore.exceptions import ClientError
import binascii
import boto3
import datetime
import json
import requests
import os

from ..utils.exceptions import ApplicationException
from ..utils.xray import xray_recorder

_lambda_client = boto3.client('lambda')
_ses_client = boto3.client('ses')
_sqs_client = boto3.client('sqs')


@xray_recorder.capture('fathomapi.comms._transport.invoke_lambda_sync')
def invoke_lambda_sync(function_name, version, payload=None):
    """
    Invoke a lambda function synchronously
    :param str function_name: The lambda function name or ARN to call.  Environment variables will be interpolated.
    :param str version: The version of the function to call
    :param dict payload: The payload to call with
    :return: dict
    """
    res = _lambda_client.invoke(
        FunctionName=f'{function_name}:{version}'.format(**os.environ),
        Payload=json.dumps(payload or {}),
    )
    return json.loads(res['Payload'].read().decode('utf-8'))


@xray_recorder.capture('fathomapi.comms._transport.invoke_apigateway_sync')
def invoke_apigateway_sync(service, version, method, endpoint, body=None, headers=None):
    """
    Make an HTTP request to an API Gateway endpoint synchronously
    :param str service:
    :param str version:
    :param str method: HTTP method
    :param str endpoint: Query path
    :param dict body:
    :param dict headers:
    :return:
    """
    url = f"https://apis.{os.environ['ENVIRONMENT']}.fathomai.com/{service}/{version}/{endpoint}"
    encoded_body = '' if body is None else json.dumps(body)
    all_headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'Fathomai API {SERVICE}:{AWS_LAMBDA_FUNCTION_VERSION}'.format(**os.environ)
    }
    all_headers.update(headers or {})

    response = requests.request(method, url, data=encoded_body, headers=all_headers)

    # TODO validation
    return response.json()


@xray_recorder.capture('fathomapi.comms._transport.push_sqs_sync')
def push_sqs_sync(queue_name, payloads, execute_at):
    delay_seconds = max(0, min(int((execute_at - datetime.datetime.now()).total_seconds()), 15*60))
    _sqs_client.send_message_batch(
        QueueUrl=f'https://sqs.{{AWS_REGION}}.amazonaws.com/{{AWS_ACCOUNT_ID}}/{queue_name}'.format(**os.environ),
        Entries=[{
            'MessageBody': json.dumps(payload),
            'DelaySeconds': delay_seconds,
            'Id': binascii.b2a_hex(os.urandom(16)).decode(),
        } for payload in payloads]
    )


@xray_recorder.capture('fathomapi.comms._transport.push_sqs_sync')
def send_ses_email(recipient, subject, text, source='noreply@fathomai.com'):
    _ses_client.send_email(
        Source=source,
        Destination={'ToAddresses': [recipient]},
        Message={
            'Subject': {'Data': subject},
            'Body': {
                'Text': {'Data': text},
            },
        }
    )


@xray_recorder.capture('fathomapi.comms._transport.get_secretsmanager_secret')
def get_secretsmanager_secret(secret_name):
    client = boto3.client('secretsmanager')
    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
    except ClientError as e:
        raise ApplicationException('SecretsManagerError', json.dumps(e.response), 500)
    else:
        if 'SecretString' in get_secret_value_response:
            return json.loads(get_secret_value_response['SecretString'])
        else:
            return get_secret_value_response['SecretBinary']
