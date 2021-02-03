import json
import os
from uuid import uuid4

import boto3
import pytest
from moto import mock_logs  # type: ignore
from pytest_mock import MockerFixture

from cybersecuritytools.csls.generate_cloudwatch_logs import put_cloudwatch_logs

from .put_cloudwatch_logs import (
    log_formats,
    log_group_name,
    log_lines,
    send_logs_to_cloudwatch,
    setup_cloudwatch_log_groups,
)

FORMATS = ["json", "csv", "raw", "syslog"]


@pytest.mark.parametrize("fmt", FORMATS)
def test_generate_log_lines(fmt: str) -> None:

    uuid = str(uuid4())
    logs = log_lines(uuid)
    assert fmt in logs.logs
    assert uuid in logs.logs[fmt]


def test_generate_log_lines_json() -> None:
    """Should return valid json for "json" format"""
    assert json.loads(log_lines(str(uuid4())).logs["json"])


@pytest.mark.parametrize("fmt", FORMATS)
def test_log_formats(fmt: str) -> None:
    """Check that all expected log formats are returned"""
    assert fmt in log_formats()


@pytest.mark.skip(reason="put_subscription_filter is NotImplemented by moto")
def test_create_cloudwatch_log_group() -> None:
    pass


@pytest.mark.parametrize("fmt", FORMATS + ["general"])
def test_setup_cloudwatch_log_groups(fmt: str, mocker: MockerFixture) -> None:
    """A CloudWatchLog group should be created for each format"""
    mocker.patch(f"{__package__}.put_cloudwatch_logs.create_cloudwatch_log_group")

    d = "dest"
    r = "role"
    setup_cloudwatch_log_groups(d, r)

    call = mocker.call(f"/gds/test/{fmt}", d, r)
    assert call in put_cloudwatch_logs.create_cloudwatch_log_group.mock_calls  # type: ignore # noqa: E501


def test_log_group_name() -> None:
    postfix = "foobar"
    assert "/gds/test/foobar" == log_group_name(postfix)


@mock_logs  # type: ignore
@pytest.mark.parametrize("file_format", FORMATS + ["general"])
def test_send_logs_to_cloudwatch(file_format: str, mocker: MockerFixture) -> None:
    """"Check ClouldWatchLogResults objects are created for the expected formats"""
    os.environ["AWS_DEFAULT_REGION"] = "eu-west-1"
    # Create log groups for test
    client = boto3.client("logs")

    for file_format in ["general"] + log_formats():
        client.create_log_group(logGroupName=log_group_name(file_format))

    results = send_logs_to_cloudwatch()
    assert file_format in results
    assert results[file_format].payload
    assert results[file_format].timestamp_ms
