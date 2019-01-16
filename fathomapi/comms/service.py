import datetime
import json
import random

from .transport import invoke_lambda_sync, invoke_apigateway_sync, push_sqs_sync
from ..utils.formatters import format_datetime
from ..utils.xray import xray_recorder


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

    @xray_recorder.capture('fathomapi.comms.service.call_apigateway_async')
    def call_apigateway_async(self, method, endpoint, body=None, execute_at=None):
        return self.call_apigateway_async_multi([{'method': method, 'endpoint': endpoint, 'body': body}], execute_at)

    @xray_recorder.capture('fathomapi.comms.service.call_apigateway_async_multi')
    def call_apigateway_async_multi(self, calls, execute_at=None, jitter=0):
        if execute_at is None:
            execute_at = datetime.datetime.now()
        service_token = _get_service_token()

        for i in range(0, len(calls), 10):
            jitter_offset = datetime.timedelta(seconds=random.randint(0, jitter))
            payloads = [{
                "path": f"/{self.name}/{self.version}/{call['endpoint'].strip('/')}",
                "httpMethod": call['method'],
                "headers": {
                    "Accept": "*/*",
                    "Authorization": service_token,
                    "Content-Type": "application/json",
                    "User-Agent": f"Biometrix/API {self.name}:{self.version}",
                    "X-Execute-At": format_datetime(execute_at + jitter_offset),
                    "X-Api-Version": self.version,
                },
                "pathParameters": {"endpoint": call['endpoint'].strip('/')},
                "stageVariables": {"LambdaAlias": self.version},
                "body": json.dumps(call['body']) if call['body'] is not None else None,
                "isBase64Encoded": False
            } for call in calls[i:i+10]]

            push_sqs_sync(f'{self.name}-{{ENVIRONMENT}}-apigateway-async', payloads, execute_at + jitter_offset)

    @xray_recorder.capture('fathomapi.comms.service.call_lambda_sync')
    def call_lambda_sync(self, function_name, payload=None):
        return invoke_lambda_sync(f'{self.name}-{{ENVIRONMENT}}-{function_name}', self.version, payload)


_service_token = None
_service_token_expiry = None


@xray_recorder.capture('fathomapi.comms.service._get_service_token')
def _get_service_token():
    global _service_token, _service_token_expiry
    if _service_token is None or _service_token_expiry < datetime.datetime.now():
        _service_token = invoke_lambda_sync('users-{ENVIRONMENT}-apigateway-serviceauth', '2_0')['token']
        _service_token_expiry = datetime.datetime.now() + datetime.timedelta(minutes=10)
    return _service_token
