import json

from ..utils.xray import xray_recorder, TraceHeader
from .config import Config
from .flask_app import app


def handler(event, context):
    if Config.get('ENVIRONMENT') != 'production':
        print(json.dumps(event))

    Config.set('API_VERSION', event['stageVariables']['LambdaAlias'])

    # Pass tracing info to X-Ray
    xray_trace_name = f"{Config.get('SERVICE')}.{Config.get('ENVIRONMENT')}.fathomai.com"
    if 'X-Amzn-Trace-Id-Safe' in event['headers']:
        xray_trace = TraceHeader.from_header_str(event['headers']['X-Amzn-Trace-Id-Safe'])
        xray_recorder.begin_segment(
            name=xray_trace_name,
            traceid=xray_trace.root,
            parent_id=xray_trace.parent
        )
    else:
        xray_recorder.begin_segment(name=xray_trace_name)

    xray_recorder.current_segment().put_http_meta('url', f"https://apis.{Config.get('ENVIRONMENT')}.fathomai.com/{Config.get('SERVICE')}/{Config.get('API_VERSION')}{event['path']}")
    xray_recorder.current_segment().put_http_meta('method', event['httpMethod'])
    xray_recorder.current_segment().put_http_meta('user_agent', event['headers']['User-Agent'])
    xray_recorder.current_segment().put_annotation('environment', Config.get('ENVIRONMENT'))
    xray_recorder.current_segment().put_annotation('version', str(Config.get('API_VERSION')))

    ret = app(event, context)
    ret['headers'].update({
        'Access-Control-Allow-Methods': 'DELETE,GET,HEAD,OPTIONS,PATCH,POST,PUT',
        'Access-Control-Allow-Headers': 'Content-Type,Authorization,X-Amz-Date,X-Api-Key,X-Amz-Security-Token',
        'Access-Control-Allow-Origin': '*',
    })

    # Unserialise JSON output so AWS can immediately serialise it again...
    ret['body'] = ret['body'].decode('utf-8')

    if ret['headers']['Content-Type'] == 'application/octet-stream':
        ret['isBase64Encoded'] = True

    # xray_recorder.current_segment().http['response'] = {'status': ret['statusCode']}
    xray_recorder.current_segment().put_http_meta('status', ret['statusCode'])
    xray_recorder.current_segment().apply_status_code(ret['statusCode'])
    xray_recorder.end_segment()

    if Config.get('ENVIRONMENT') != 'production':
        print(json.dumps(ret))
    return ret
