from aws_xray_sdk.core import xray_recorder
from flask import request
import datetime
import json

from ._transport import invoke_lambda_sync, invoke_apigateway_sync, push_sqs_sync
from ..utils.formatters import format_datetime


class Service:
    def __init__(self, name, version):
        self.name = name
        self.version = version

    @xray_recorder.capture('fathomapi.comms.service.call_apigateway_sync')
    def call_apigateway_sync(self, method, endpoint, body=None, headers=None):
        if headers is None:
            headers = {}
        headers.update({'Authorization': _get_service_token()})

        return invoke_apigateway_sync(self.name, self.version, method, endpoint, body, headers)

    def call_apigateway_async(self, method, endpoint, body=None, execute_at=None):
        if execute_at is None:
            execute_at = datetime.datetime.now()
        endpoint = endpoint.strip('/')
        payload = {
            "path": f"/{self.name}/{self.version}/{endpoint}",
            "httpMethod": method,
            "headers": {
                "Accept": "*/*",
                "Authorization": request.headers.get('Authorization', None),
                "Content-Type": "application/json",
                "User-Agent": f"Biometrix/API {self.name}:{self.version}",
                "X-Execute-At": format_datetime(execute_at),
                "X-Api-Version": self.version,
            },
            "pathParameters": {"endpoint": endpoint},
            "stageVariables": {"LambdaAlias": self.version},
            "body": json.dumps(body) if body is not None else None,
            "isBase64Encoded": False
        }

        push_sqs_sync(f'{self.name}-{{ENVIRONMENT}}-apigateway-async', payload)

    def call_lambda_sync(self, function_name, payload=None):
        return invoke_lambda_sync(f'{self.name}-{{ENVIRONMENT}}-{function_name}', self.version, payload)


@xray_recorder.capture('fathomapi.comms.service._get_service_token')
def _get_service_token():
    return invoke_lambda_sync('users-{ENVIRONMENT}-apigateway-serviceauth', '1_0')['token']
