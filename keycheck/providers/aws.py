"""AWS provider — validate credentials and fetch CloudTrail events.

Requires both Access Key ID and Secret Access Key.
The secret key is handled via SecureBytes and never logged.
"""

from __future__ import annotations

from typing import Any

from keycheck.core.vault import SecureBytes


def audit(access_key: SecureBytes, secret_key: SecureBytes, region: str = "us-east-1") -> dict[str, Any]:
    """Validate AWS credentials and retrieve last CloudTrail events."""
    try:
        import boto3
        from botocore.exceptions import ClientError, NoCredentialsError
    except ImportError:
        return {
            "valid": False,
            "summary": "boto3 not installed. Run: pip install boto3",
            "events": [],
        }

    ak = access_key.to_str()
    sk = secret_key.to_str()

    try:
        session = boto3.Session(
            aws_access_key_id=ak,
            aws_secret_access_key=sk,
            region_name=region,
        )
        sts = session.client("sts")
        identity = sts.get_caller_identity()

        ct = session.client("cloudtrail")
        trail_events = ct.lookup_events(MaxResults=20)
        events = trail_events.get("Events", [])

        parsed = [
            {
                "event_name": e.get("EventName"),
                "event_time": str(e.get("EventTime")),
                "username": e.get("Username"),
                "source_ip": e.get("CloudTrailEvent", "{}"),
            }
            for e in events
        ]

        return {
            "valid": True,
            "account_id": identity.get("Account"),
            "arn": identity.get("Arn"),
            "summary": f"Active. Account: {identity.get('Account')}. Last {len(events)} CloudTrail events retrieved.",
            "events": parsed,
        }

    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code in ("InvalidClientTokenId", "AuthFailure"):
            return {"valid": False, "summary": "Credentials invalid or revoked.", "events": []}
        return {"valid": False, "summary": f"AWS error: {code}", "events": []}
    except NoCredentialsError:
        return {"valid": False, "summary": "No credentials provided.", "events": []}
    finally:
        del ak, sk
