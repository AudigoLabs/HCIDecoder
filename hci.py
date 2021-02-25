from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame

from abc import ABC, abstractmethod, abstractproperty
from itertools import chain
import struct


LE_OPCODE_DESC = {
    0x2001: "LE Set Event Mask",
    0x2002: "LE Read Buffer Size",
    0x2003: "LE Read Local Supported Features",
    0x2005: "LE Set Random Address",
    0x2006: "LE Set Advertising Parameters",
    0x2007: "LE Read Advertising Channel TX Power",
    0x2008: "LE Set Advertising Data",
    0x2009: "LE Set Scan Response Data",
    0x200A: "LE Set Advertise Enable",
    0x200B: "LE Set Scan Parameters",
    0x200C: "LE Set Scan Enable",
    0x200D: "LE Create Connection",
    0x200E: "LE Create Connection Cancel",
    0x200F: "LE Read White List Size",
    0x2010: "LE Clear White Lis",
    0x2011: "LE Add Device To White List",
    0x2012: "LE Remove Device From White List",
    0x2013: "LE Connection Update",
    0x2014: "LE Set Host Channel Classification",
    0x2015: "LE Read Channel Map",
    0x2016: "LE Read Remote Used Features",
    0x2017: "LE Encrypt",
    0x2018: "LE Rand",
    0x2019: "LE Start Encryption",
    0x201A: "LE Long Term Key Requested Reply",
    0x201B: "LE Long Term Key Requested Negative Reply",
    0x201C: "LE Read Supported States",
    0x201D: "LE Receiver Test",
    0x201E: "LE Transmitter Test",
    0x201F: "LE Test End Command",
    0x2020: "LE Remote Connection Parameter Request Reply",
    0x2021: "LE Remote Connection Parameter Request Negative Reply",
    0x2022: "LE Set Data Length",
    0x2023: "LE Read Suggested Default Data Length",
    0x2024: "LE Write Suggested Default Data Length",
    0x2026: "LE Read Local P256 Public Key 37 0x2025 LE Generate DHKey",
    0x2027: "LE Add Device to Resolving List",
    0x2028: "LE Remove Device from Resolving List",
    0x2029: "LE Clear Resolving List",
    0x202A: "LE Read Resolving List Size",
    0x202B: "LE Read Peer Resolvable Address",
    0x202C: "LE Read Local Resolvable Address",
    0x202D: "LE Set Address Resolution Enable",
    0x202E: "LE Set Resolvable Private Address Timeout",
    0x202F: "LE Read Maximum Data Length",
}

BT_EVENT_DESC = {
    0x05: "Disconnection Complete",
    0x08: "Encryption Change",
    0x0C: "Read Remote Version Information Complete",
    0x0E: "Command Complete",
    0x0F: "Command Status",
    0x10: "Hardware Error",
    0x13: "Number of Completed Packets",
    0x1A: "Data Buffer Overflow",
    0x30: "Encryption Key Refresh Complete",
    0x57: "Authenticated Payload Timeout Expired",
}

LE_SUBEVENT_DESC = {
    0x01: "LE Connection Complete",
    0x02: "LE Advertising Report",
    0x03: "LE Connection Update Complete",
    0x04: "LE Read Remote Used Features Complete",
    0x05: "LE Long Term Key Requested",
    0x06: "LE Remote Connection Parameter Request",
    0x07: "LE Data Length Change",
    0x08: "LE Read Local P256 Public Key Complete",
    0x09: "LE Generate DHKey Complete",
    0x0A: "LE Enhanced Connection Complete",
    0x0B: "LE Direct Advertising Report",
}


class Packet(ABC):
    HEADER_FMT = None
    RESULT_TYPES = None

    def __init__(self):
        assert self.HEADER_FMT
        self._header_temp = b''
        self._header = None
        self._data = b''

    def process_data(self, data):
        while data:
            if not self._header:
                header_size = struct.calcsize(self.HEADER_FMT)
                new_header_bytes = min(header_size - len(self._header_temp), len(data))
                self._header_temp += data[:new_header_bytes]
                data = data[new_header_bytes:]
                if len(self._header_temp) < header_size:
                    # Not enough data yet
                    assert len(data) == 0
                    return False
                # Decode the header
                self._header = struct.unpack(self.HEADER_FMT, self._header_temp)
            # Process the data
            self._data += data
            return len(self._data) == self._header[-1]

    def get_analyzer_frame(self, start_time, end_time):
        pass


class CommandPacket(Packet):
    HEADER_FMT = "<HB"
    RESULT_TYPES = {'command': "{{data.packet_type}} ({{data.operation}} | length={{data.length}})"}

    def get_analyzer_frame(self, start_time, end_time):
        opcode, param_len = self._header
        return AnalyzerFrame('command', start_time, end_time, {
            'packet_type': "Command",
            'operation': LE_OPCODE_DESC.get(opcode, "Unknown Opcode"),
            'length': param_len,
        })


class AsynchronousDataPacket(Packet):
    HEADER_FMT = "<HH"
    RESULT_TYPES = {'async': "{{data.packet_type}} (CID={{data.cid}}, length={{data.length}}, data={{data.data}})"}

    def get_analyzer_frame(self, start_time, end_time):
        assert len(self._data) >= 4
        data_len, cid = struct.unpack("<HH", self._data[:4])
        data = self._data[4:]
        assert data_len == len(data)
        if data_len > 4:
            data_bytes_str = ''.join([f"{b:02X}" for b in data[:4]]) + "..."
        else:
            data_bytes_str = ''.join([f"{b:02X}" for b in data])
        return AnalyzerFrame('async', start_time, end_time, {
            'packet_type': "Async Data",
            'cid': cid,
            'length': data_len,
            'data': data_bytes_str,
        })


class EventPacket(Packet):
    HEADER_FMT = "BB"
    RESULT_TYPES = {'event': "{{data.packet_type}} ({{data.operation}})"}

    def get_analyzer_frame(self, start_time, end_time):
        event_code = self._header[0]
        if event_code in BT_EVENT_DESC:
            if event_code == 0x0E:
                assert len(self._data) >= 3
                num_packets = self._data[0]
                opcode = struct.unpack("<H", self._data[1:3])[0]
                status = self._data[3]
                opcode_str = LE_OPCODE_DESC[opcode] if opcode in LE_OPCODE_DESC else f"Unknown Opcode"
                status_str = "Success" if status == 0 else f"Error {hex(status)}"
                event_str = f"Command Complete | {status_str} | {opcode_str}"
            else:
                event_str = BT_EVENT_DESC[event_code]
        elif event_code == 0x3e:
            # LE event
            assert len(self._data) >= 1
            subevent = self._data[0]
            if subevent in LE_SUBEVENT_DESC:
                event_str = LE_SUBEVENT_DESC[subevent]
            else:
                event_str = f"Unknown LE Event"
        else:
            event_str = f"Unknown Event"
        return AnalyzerFrame('event', start_time, end_time, {
            'packet_type': "Event",
            'operation': event_str,
        })


# Define all the supported packets by their type
PACKETS = {
    0x01: CommandPacket,
    0x02: AsynchronousDataPacket,
    0x04: EventPacket,
}

# Collect all the result types
RESULT_TYPES = {}
for p in PACKETS.values():
    RESULT_TYPES.update({k: {'format': v} for k, v in p.RESULT_TYPES.items()})


class HciHla(HighLevelAnalyzer):
    result_types = RESULT_TYPES

    def __init__(self):
        self._packet = None
        self._start_time = None

    def decode(self, frame: AnalyzerFrame):
        if frame.type != 'data':
            # Only care about data frame
            return
        if 'error' in frame.data:
            # Ignore error frames (i.e. framing / parity errors)
            return
        data = frame.data['data']
        if not self._packet:
            # This is the start of a new packet - determine the type based on the first byte
            packet_class = PACKETS.get(data[0], None)
            if not packet_class:
                return AnalyzerFrame('unknown', frame.start_time, frame.end_time, {})
            self._start_time = frame.start_time
            self._packet = packet_class()
        elif self._packet.process_data(data):
            # This is the end of the packet
            result = self._packet.get_analyzer_frame(self._start_time, frame.end_time)
            self._packet = None
            self._start_time = None
            return result
