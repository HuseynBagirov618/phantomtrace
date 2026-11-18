"""Route Windows event records by their embedded source identity."""
from phantomtrace.normalization.auth import normalize_auth_event
from phantomtrace.normalization.common import event_data_fields, normalize_timestamp
from phantomtrace.normalization.powershell import normalize_powershell_event
from phantomtrace.normalization.sysmon import normalize_sysmon_event


def normalize_windows_event(record):
    channel = (record.get("channel") or "").casefold()
    provider = (record.get("provider") or "").casefold()
    code = str(record.get("event_id"))
    if channel == "microsoft-windows-sysmon/operational" and provider == "microsoft-windows-sysmon":
        return normalize_sysmon_event(record)
    if channel in {"microsoft-windows-powershell/operational", "powershellcore/operational"} and provider in {
        "microsoft-windows-powershell", "powershellcore",
    }:
        return normalize_powershell_event(record)
    if channel == "security" and provider == "microsoft-windows-security-auditing":
        if code in {"4624", "4625"}:
            return normalize_auth_event(record)
        if code == "4688":
            return security_observation(record, "security_process_creation", {
                "process.executable": "NewProcessName",
                "process.command_line": "CommandLine",
                "process.pid": "NewProcessId",
            })
        if code == "4698":
            return security_observation(record, "scheduled_task_creation", {
                "task.name": "TaskName",
                "winlog.logon.id": "SubjectLogonId",
                "user.sid": "SubjectUserSid",
                "user.name": "SubjectUserName",
                "user.domain": "SubjectDomainName",
                "task.client_process_id": "ClientProcessId",
                "task.client_process_start_key": "ClientProcessStartKey",
            })
    if channel == "system" and provider == "microsoft-windows-kernel-general" and code == "12":
        return security_observation(record, "boot_started", {
            "system.boot_started": "StartTime",
        })
    return None


def security_observation(record, event_type, mappings):
    fields = event_data_fields(record)
    normalized = {key: fields.get(value) for key, value in mappings.items()}
    warnings = [f"missing field: {key}" for key, value in normalized.items() if value in (None, "", "-")]
    return {
        **normalized,
        "event_type": event_type,
        "event.code": str(record["event_id"]),
        "@timestamp": normalize_timestamp(record.get("timestamp")),
        "timestamp_original": record.get("timestamp"),
        "host.name": record.get("computer"),
        "winlog.channel": record.get("channel"),
        "winlog.provider_name": record.get("provider"),
        "winlog.record_id": record.get("record_id"),
        "winlog.event_data": fields,
        "pt": {"parse_warnings": warnings},
    }
