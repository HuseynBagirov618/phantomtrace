import json
import sys
from pathlib import Path
from xml.etree import ElementTree as ET

from Evtx.Evtx import Evtx


EVENT_NS = {
    "e": "http://schemas.microsoft.com/win/2004/08/events/event"
}


def parse_evtx(file_path: str, limit: int | None = None, *, continue_on_error=False):
    """Yield Windows EVTX records with metadata, EventData, and source XML.

    With continue_on_error, individual record failures include their physical offset.
    The original EVTX file remains the authoritative source of evidence.
    """
    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(file_path)

    if limit is not None and limit < 0:
        raise ValueError("limit must be non-negative")

    if limit == 0:
        return

    if path.stat().st_size < 4096 or (path.stat().st_size - 4096) % 65536:
        raise ValueError("Incomplete EVTX file header or chunk")
    with Evtx(str(path)) as log:
        for index, record in enumerate(log.records()):
            if limit is not None and index >= limit:
                break

            try:
                yield decode_record(record, path)
            except Exception as error:
                if not continue_on_error:
                    raise
                yield {"parse_error": type(error).__name__, "offset": record.offset(),
                       "record_id": record.record_num()}


def decode_record(record, path):
    xml_text = record.xml()
    root = ET.fromstring(xml_text)
    system = root.find("e:System", EVENT_NS)

    if system is None:
        raise ValueError("Missing System element")

    def get_text(element_name: str):
        node = system.find(f"e:{element_name}", EVENT_NS)
        return node.text if node is not None else None

    provider_node = system.find("e:Provider", EVENT_NS)
    timestamp_node = system.find("e:TimeCreated", EVENT_NS)

    event_data = []
    event_data_node = root.find("e:EventData", EVENT_NS)
    if event_data_node is not None:
        for data_node in event_data_node.findall("e:Data", EVENT_NS):
            event_data.append({
                "name": data_node.get("Name"),
                "value": data_node.text,
            })

    event = {
        "event_id": get_text("EventID"),
        "record_id": get_text("EventRecordID"),
        "timestamp": (
            timestamp_node.get("SystemTime")
            if timestamp_node is not None else None
        ),
        "provider": (
            provider_node.get("Name")
            if provider_node is not None else None
        ),
        "computer": get_text("Computer"),
        "channel": get_text("Channel"),
        "source_file": path.name,
        "event_data": event_data,
        "raw_xml": xml_text,
    }
    event["offset"] = record.offset()
    return event


def main():
    # On POSIX, limit the worker independently of the API process.
    try:
        import resource
    except ImportError:
        resource = None
    if resource:
        ceiling = 512 * 1024 * 1024
        _, hard = resource.getrlimit(resource.RLIMIT_AS)
        if hard != resource.RLIM_INFINITY:
            ceiling = min(ceiling, hard)
        resource.setrlimit(resource.RLIMIT_AS, (ceiling, ceiling))
        if hasattr(resource, "RLIMIT_FSIZE"):
            limit = 256 * 1024 * 1024
            _, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
            if hard != resource.RLIM_INFINITY:
                limit = min(limit, hard)
            resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
    try:
        for event in parse_evtx(sys.argv[1], continue_on_error=True):
            print(json.dumps(event))
    except Exception as error:
        print(type(error).__name__, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
