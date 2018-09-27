from aws_xray_sdk.core import xray_recorder
import os

from ._transport import invoke_lambda_sync


@xray_recorder.capture('fathomapi.comms.legacy.query_postgres')
def query_postgres_sync(query, parameters):
    return multiquery_postgres_sync([(query, parameters)])[0]


@xray_recorder.capture('fathomapi.comms.legacy.query_postgres')
def multiquery_postgres_sync(query_sets):
    res = invoke_lambda_sync(
        'infrastructure-{ENVIRONMENT}-querypostgres',
        '$LATEST',  # TODO
        {
            "Queries": [{"Query": query, "Parameters": parameters} for query, parameters in query_sets],
            "Config": {"ENVIRONMENT": os.environ['ENVIRONMENT']}
        }
    )
    if len(list(filter(None, res['Errors']))):
        raise Exception(list(filter(None, res['Errors'])))
    else:
        return res['Results']
