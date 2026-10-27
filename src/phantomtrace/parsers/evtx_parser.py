from pathlib import Path
from xml.etree import ElementTree as ET

from Evtx.Evtx import Evtx


EVENT_NS = {
    "e": "http://schemas.microsoft.com/win/2004/08/events/event"
}


def parse_evtx(file_path: str, limit: int | None = None):
    """Yield Windows EVTX records with metadata, EventData, and source XML.

    Record parsing errors propagate rather than silently skipping evidence.
    The original EVTX file remains the authoritative source of evidence.
    """
    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(file_path)

    if limit is not None and limit < 0:
        raise ValueError("limit must be non-negative")

    if limit == 0:
        return

    with Evtx(str(path)) as log:
        for index, record in enumerate(log.records()):
            if limit is not None and index >= limit:
                break

            xml_text = record.xml()
            root = ET.fromstring(xml_text)
            system = root.find("e:System", EVENT_NS)

            if system is None:
                raise ValueError(f"Missing System element in record {index}")

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
            yield event
