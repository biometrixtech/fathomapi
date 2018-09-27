# Copyright 2016 Matt Martz, 2018 Stephen Poole
# All Rights Reserved.
#
# This file contains code from the Flask-Lambda library (https://github.com/sivel/flask-lambda)
# released under the Apache License, Version 2.0 (the "License").
#
# Remaining code Copyright Melon Software Ltd, used under license

from flask import Flask, Response, jsonify
from io import StringIO
from urllib.parse import urlencode
from werkzeug.wrappers import BaseRequest
import json
import sys
import traceback

from .converters import UuidConverter
from ..utils.exceptions import ApplicationException
from ..utils.serialisable import json_serialise


class LambdaResponse(object):
    def __init__(self):
        self.status = None
        self.response_headers = None

    def start_response(self, status, response_headers, exc_info=None):
        self.status = int(status[:3])
        self.response_headers = dict(response_headers)


class FlaskLambda(Flask):
    def __call__(self, event, context):
        if 'httpMethod' not in event:
            # In this "context" `event` is `environ` and
            # `context` is `start_response`, meaning the request didn't
            # occur via API Gateway and Lambda
            return super(FlaskLambda, self).__call__(event, context)

        response = LambdaResponse()

        body = next(self.wsgi_app(
            self._make_environ(event),
            response.start_response
        ))

        return {
            'statusCode': response.status,
            'headers': response.response_headers,
            'body': body
        }

    @staticmethod
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


class ApiResponse(Response):
    @classmethod
    def force_type(cls, rv, environ=None):
        if isinstance(rv, dict):
            # Round-trip through our JSON serialiser to make it parseable by AWS's
            rv = json.loads(json.dumps(rv, sort_keys=True, default=json_serialise))
            rv = jsonify(rv)
        return super().force_type(rv, environ)


app = FlaskLambda(__name__)
app.response_class = ApiResponse
app.url_map.strict_slashes = False
app.url_map.converters['uuid'] = UuidConverter


@app.errorhandler(500)
def handle_server_error(e):
    tb = sys.exc_info()[2]
    return {'message': str(e.with_traceback(tb))}, 500, {'Status': type(e).__name__}


@app.errorhandler(400)
def handle_bad_request(_):
    return {"message": "Request not formed properly. Please check params or data."}, 400, {'Status': 'BadRequest'}


@app.errorhandler(401)
def handle_unauthorized(_):
    return {"message": "Unauthorized. Please check the email/password or authorization token."}, 401, \
           {'Status': 'Unauthorized'}


@app.errorhandler(404)
def handle_unrecognised_endpoint(_):
    return {"message": "You must specify an endpoint"}, 404, {'Status': 'UnrecognisedEndpoint'}


@app.errorhandler(405)
def handle_unrecognised_method(_):
    return {"message": "The given method is not supported for this endpoint"}, 405, {'Status': 'UnsupportedMethod'}


@app.errorhandler(ApplicationException)
def handle_application_exception(e):
    traceback.print_exception(*sys.exc_info())
    return {'message': e.message}, e.status_code, {'Status': e.status_code_text}
