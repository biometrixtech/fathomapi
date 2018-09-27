import os

# Break out of Lambda's X-Ray sandbox so we can define our own segments and attach metadata, annotations, etc, to them
lambda_task_root_key = os.getenv('LAMBDA_TASK_ROOT', ".")
if lambda_task_root_key != ".":
    del os.environ['LAMBDA_TASK_ROOT']
from aws_xray_sdk.core import patch_all, xray_recorder as _xray_recorder
from aws_xray_sdk.core.models.trace_header import TraceHeader as _TraceHeader
patch_all()
os.environ['LAMBDA_TASK_ROOT'] = lambda_task_root_key

xray_recorder = _xray_recorder
TraceHeader = _TraceHeader
