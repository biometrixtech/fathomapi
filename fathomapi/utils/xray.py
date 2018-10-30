from aws_xray_sdk.core import patch_all, xray_recorder as _xray_recorder
from aws_xray_sdk.core.models.trace_header import TraceHeader as _TraceHeader
patch_all()

xray_recorder = _xray_recorder
TraceHeader = _TraceHeader
