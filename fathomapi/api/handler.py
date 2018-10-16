from io import StringIO
from urllib.parse import urlencode
from werkzeug.wrappers import BaseRequest
import json
import sys

from ..utils.xray import xray_recorder, TraceHeader
from .config import Config
from .flask_app import app


def handler(event, context):
    if Config.get('ENVIRONMENT') != 'production':
        print(json.dumps(event))

    if 'eventSourceARN' in event['requestContext'] and 'sqs' in event['requestContext']['eventSourceARN']:
        # An asynchronous invocation from SQS
        print('Asynchronous invocation')
        event['headers']['X-Source'] = 'sqs'
    else:
        print('API Gateway invocation')
        event['headers']['X-Source'] = 'apigateway'

    Config.set('API_VERSION', event['stageVariables']['LambdaAlias'])

    response = LambdaResponse()

    ret = app(_make_environ(event), response.start_response)

    body = next(ret).decode('utf-8') if int(response.headers.get('Content-Length', 0)) > 0 else ''  # Don't try to get body content if there isn't any
    ret = response.to_lambda(body)

    if Config.get('ENVIRONMENT') != 'production':
        print(json.dumps(ret))
    return ret


class LambdaResponse(object):
    def __init__(self):
        self.status = None
        self.headers = {
            'Access-Control-Allow-Methods': 'DELETE,GET,HEAD,OPTIONS,PATCH,POST,PUT',
            'Access-Control-Allow-Headers': 'Content-Type,Authorization,X-Amz-Date,X-Api-Key,X-Amz-Security-Token',
            'Access-Control-Allow-Origin': '*',
        }

    def start_response(self, status, response_headers):
        self.status = int(status[:3])
        self.headers.update(dict(response_headers))

    def to_lambda(self, body):
        return {
            'statusCode': self.status,
            'headers': self.headers,
            'body': body,
            'isBase64Encoded': self.headers['Content-Type'] == 'application/octet-stream'
        }


def _make_environ(event):
    environ = {
        'HOST': 'apigateway:443',
        'HTTP_HOST': 'apigateway:443',
        'HTTP_X_FORWARDED_PORT': '443',
        'SCRIPT_NAME': '',
        'SERVER_PORT': '443',
        'SERVER_PROTOCOL': 'HTTP/1.1',
    }

    for header_name, header_value in event['headers'].items():
        header_name = header_name.replace('-', '_').upper()
        if header_name in ['CONTENT_TYPE', 'CONTENT_LENGTH']:
            environ[header_name] = header_value
        else:
            environ[('HTTP_%s' % header_name)] = header_value

    qs = event.get('queryStringParameters', None)

    environ['REQUEST_METHOD'] = event['httpMethod']
    environ['PATH_INFO'] = event['pathParameters']['endpoint']
    environ['QUERY_STRING'] = urlencode(qs) if qs else ''
    environ['REMOTE_ADDR'] = event.get('requestContext', {}).get('identity', {}).get('sourceIp', '0.0.0.0')

    environ['CONTENT_LENGTH'] = str(
        len(event['body']) if event['body'] else ''
    )

    environ['wsgi.url_scheme'] = 'https'
    environ['wsgi.input'] = StringIO(event['body'] or '')
    environ['wsgi.version'] = (1, 0)
    environ['wsgi.errors'] = sys.stderr
    environ['wsgi.multithread'] = False
    environ['wsgi.run_once'] = True
    environ['wsgi.multiprocess'] = False

    BaseRequest(environ)

    return environ
