# Copyright 2016 Matt Martz, 2018 Stephen Poole
# All Rights Reserved.
#
# This file contains code from the Flask-Lambda library (https://github.com/sivel/flask-lambda)
# released under the Apache License, Version 2.0 (the "License").
#
# Remaining code Copyright Melon Software Ltd, used under license

from flask import Flask, request, Response, jsonify
import json
import sys
import traceback

from ..utils.exceptions import ApplicationException
from ..utils.serialisable import json_serialise
from ..utils.xray import xray_recorder, TraceHeader
from .config import Config
from .converters import UuidConverter, VersionNumberConverter, Mac4AddressConverter, Mac6AddressConverter


class FlaskLambda(Flask):
    pass


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
app.url_map.converters['semver'] = VersionNumberConverter
app.url_map.converters['mac4'] = Mac4AddressConverter
app.url_map.converters['mac6'] = Mac6AddressConverter


@app.before_request
def before_request():
    # Pass tracing info to X-Ray
    service = Config.get('SERVICE')
    environment = Config.get('ENVIRONMENT')
    version = str(Config.get('API_VERSION'))

    xray_trace_name = f"{service}.{environment}.fathomai.com"
    if 'X-Amzn-Trace-Id-Safe' in request.headers:
        xray_trace = TraceHeader.from_header_str(request.headers['X-Amzn-Trace-Id-Safe'])
        xray_recorder.begin_subsegment(
            name=xray_trace_name,
            traceid=xray_trace.root,
            parent_id=xray_trace.parent
        )
    else:
        xray_recorder.begin_subsegment(name=xray_trace_name)

    xray_recorder.current_subsegment().put_annotation('environment', environment)
    xray_recorder.current_subsegment().put_annotation('version', version)
    xray_recorder.current_subsegment().put_annotation('code_version', _get_code_version())


@app.after_request
def after_request(response):
    status = int(response.status[:3])
    xray_recorder.current_subsegment().put_http_meta('status', status)
    xray_recorder.current_subsegment().apply_status_code(status)
    xray_recorder.end_subsegment()

    return response


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


def _get_code_version():
    try:
        with open('version', 'r') as f:
            return f.read()
    except FileNotFoundError:
        return '0' * 40
    except Exception as e:
        print(e)
        return '???'
