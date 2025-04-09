BIG_ENDIAN_PCAP_HEADER = 0xA1B2C3D4
LITTLE_ENDIAN_PCAP_HEADER = 0xD4C3B2A1
PCAPNG_HEADER=0xa0d0d0a

# Imports the enum class from pcap_types.py
from core.pcap_types import  *
from core.parseutils import  *
from core.transfer_type import *

class USBParser(ParseUtils):
    def __init__(self):
        super().__init__()

        self._pcap_record_fields = {
            "timestamp" : self.read_dword,
            "time_microseconds" : self.read_dword,
            "octet_len": self.read_dword,
            "frame_len" : self.read_dword,
            "frame_buff" : self.read_bytes,
        }

        self._urb_fields = {
            "pseudo_header": self.get_word,
            "irp_id": self.get_qword,
            "status": self.get_dword,
            "urb_function": self.get_word,
            "irp_info": self.get_byte,
            "usb_bus_id": self.get_word,
            "device_address": self.get_word,
            "endpoint": self.get_byte,
            "urb_transfer_type": self.get_byte,
            "pkt_data_len": self.get_dword,
            "pkt_data": self.get_bytes,
            "pseudo_ip": self._format_pseudo_ip,
        }

        self._linux_mapped_urb_fields = {
            "urb_id": self.get_qword,
            "urb_type": self.get_byte,
            "urb_transfer_type": self.get_byte,
            "endpoint": self.get_byte,
            "device_address": self.get_byte,
            "usb_bus_id": self.get_word,
            "device_setup_req": self.get_byte,
            "data_present": self.get_byte,
            "urb_seconds": self.get_qword,
            "urb_useconds": self.get_dword,
            "status": self.get_dword,
            "urb_data_len": self.get_dword,
            "pkt_data_len": self.get_dword,
            "reserved": self.get_qword,
            "interval": self.get_dword,
            "sof": self.get_dword,
            "transfer_flags": self.get_dword,
            "num_iso_desc": self.get_dword,
            "pkt_data": self.get_bytes,
            "pseudo_ip": self._format_pseudo_ip,
        }

    @staticmethod
    def init_linux_mapped_urb_fields():
        return {key: None for key in [
            "urb_id", "urb_type", "urb_transfer_type", "endpoint", "device_address", "usb_bus_id", "device_setup_req", "data_present",
            "urb_seconds", "urb_useconds", "status", "urb_data_len", "pkt_data_len",
            "reserved", "interval", "sof", "transfer_flags", "num_iso_desc", "pkt_data", "pseudo_ip"
        ]}

    def _skip_frame(self):
        pass

    def _retrieve_linux_mapped_function(self, method: str):
        return self._linux_mapped_urb_fields.get(method)

    def _parse_linux_mapped_urb_fields(self, stream):
        linux_mapped_urb_fields = self.init_linux_mapped_urb_fields()
        for k, v in linux_mapped_urb_fields.items():
            if k == "pkt_data":
                # Read the leftover data
                linux_mapped_urb_fields[k] = self._retrieve_linux_mapped_function(k)(stream, linux_mapped_urb_fields['pkt_data_len'])
            elif k == "urb_transfer_type":
                linux_mapped_urb_fields[k] = self._retrieve_linux_mapped_function(k)(stream)
                # print("Transfer Type::", linux_mapped_urb_fields['urb_transfer_type'])
                # if URBTransferType(linux_mapped_urb_fields['urb_transfer_type']) != URBTransferType(0x1):
                if linux_mapped_urb_fields['urb_transfer_type'] != 0x1:
                    # Skipping the frame
                    # Resetting the counter in ParseUtils
                    self._skip_frame()
                    self.reset_count()
                    return None

            elif k == "pseudo_ip":
                linux_mapped_urb_fields[k] = self._retrieve_linux_mapped_function(k)(linux_mapped_urb_fields)
            else:
                linux_mapped_urb_fields[k] = self._retrieve_linux_mapped_function(k)(stream)
        # Decode the data accordingly
        linux_mapped_urb_fields['urb_id'] = hex(linux_mapped_urb_fields['urb_id'])
        linux_mapped_urb_fields['reserved'] = hex(linux_mapped_urb_fields['reserved'])
        linux_mapped_urb_fields['status'] = 2**32 - (linux_mapped_urb_fields['status'])

        # print(linux_mapped_urb_fields)
        self.reset_count()
        return linux_mapped_urb_fields

    @staticmethod
    def init_urb_fields():
        return {key: None for key in
                ["pseudo_header", "irp_id", "status", "urb_function", "irp_info", "usb_bus_id",
                 "device_address", "endpoint", "urb_transfer_type", "pkt_data_len", "pkt_data", "pseudo_ip"]}

    def _retrieve_function(self, method: str):
        return self._urb_fields.get(method)

    def _parse_usb_fields(self, stream: bytes):
        urb_field = self.init_urb_fields()
        for k, v in urb_field.items():
            if k == "pkt_data":
                length = urb_field['pkt_data_len']
                urb_field[k] = self._retrieve_function(k)(stream, length)
            elif k == "pseudo_ip":
                urb_field[k] = self._retrieve_function(k)(urb_field)
            else:
                urb_field[k] = self._retrieve_function(k)(stream)
        urb_field['irp_id'] = hex(urb_field['irp_id'])
        # print(urb_field)
        self.reset_count()
        return urb_field

    def read_usb(self, stream):
        return self._parse_usb_fields(stream)

    @staticmethod
    def _format_pseudo_ip(fields):
        """
            IP = bus_id + device_address + ((endpoint >> 4) & 0x0f)
        """
        ip = str(fields['usb_bus_id']) + "." + str(fields['device_address']) + "." + str(((int(fields['endpoint'])) & 0xf))
        return ip

class PCAPng(USBParser):
    def __init__(self):
        super().__init__()

        self._section_hdr_block = {
            # TODO: For PCAPng Structure (https://pcapng.com/)
            "block_type": self.read_dword,
            "block_len1": self.read_dword,
            "signature": self.read_dword,
            "major": self.read_word,
            "minor": self.read_word,
            "section_len": self.read_qword,
            "options": self.read_bytes,
            "block_len2": self.read_dword,
        }

        self._interface_desc_block = {
            "block_type": self.read_dword,
            "block_len1": self.read_dword,
            "network_type": self.read_word, # LINK TYPE
            "reserved": self.read_word,
            "snap_len": self.read_dword,
            "options": self.read_bytes,
            "block_len2": self.read_dword,
        }

        self._enhanced_packet_block = {
            "block_type": self.read_dword, # 0x00000006
            "block_len1": self.read_dword,
            "interface_id": self.read_dword,
            "timestamp_lower": self.read_dword,
            "timestamp_upper": self.read_dword,
            "cap_pkt_len": self.read_dword,
            "orig_pkt_len": self.read_dword,
            "frame_buff": self.read_bytes,
            "block_len2": self.read_dword,
        }

    @staticmethod
    def get_interface_options_size(val): return val - (0x10 +0x4 )
    @staticmethod
    def get_section_options_size(val): return val - (0x10 + 0x8 + 0x4)
    @staticmethod
    def get_enhanced_buff_size(block_len, pkt_len): return block_len - (pkt_len + 0x20) # 0x20: Remaining struct size (except frame_buff)

    @staticmethod
    def init_the_blocks(name):
        if name == "section":
            return {key:None for key in ['block_type', 'block_len1', 'signature', 'major', 'minor', 'section_len', 'options', 'block_len2'] }
        elif name == "interface":
            return {key:None for key in ['block_type', 'block_len1', 'network_type', 'reserved', 'snap_len', 'options', 'block_len2'] }
        else:
            return {key:None for key in ['block_type', 'block_len1', 'interface_id', 'timestamp_lower', 'timestamp_upper', 'cap_pkt_len', 'orig_pkt_len', 'frame_buff', 'block_len2'] }

    def parse_enhanced_block(self, stream):
        enhanced_block = self.init_the_blocks("enhanced")
        for k, v in enhanced_block.items():
            if k == "frame_buff":
                enhanced_block[k] = self._retrieve_pcapng_function("enhanced", k)(
                    stream,
                    (enhanced_block['orig_pkt_len'] +
                     self.get_enhanced_buff_size(
                         enhanced_block['block_len1'],
                         enhanced_block['orig_pkt_len']
                     ))
                )
            else:
                enhanced_block[k] = self._retrieve_pcapng_function("enhanced", k)(stream)
            if enhanced_block[k] is None: return None
        # print(self.pos,enhanced_block)
        return enhanced_block

    def _retrieve_pcapng_function(self, _name, _method):
        if _name == "section":
            return self._section_hdr_block.get(_method)
        elif _name == "interface":
            return self._interface_desc_block.get(_method)
        else:
            return self._enhanced_packet_block.get(_method)

    def parse_section_block(self, stream):
        section_hdr_block = self.init_the_blocks("section")
        for k, v in section_hdr_block.items():
            if k == "options":
                # Subtracting 0x10 (compare struct size of section_hdr and interface_block)
                section_hdr_block[k] = self._retrieve_pcapng_function("section", k)(stream, self.get_section_options_size(section_hdr_block['block_len1']))
            else:
                section_hdr_block[k] = (self._retrieve_pcapng_function("section", k)(stream))
        # print(section_hdr_block)
        return section_hdr_block

    def parse_interface_block(self, stream):
        # Ignoring the SECTION BLOCK HEADER
        # UTILIZE IT TO DUMP METADATA, NO USE HERE FOR NOW
        _ = self.parse_section_block(stream)
        interface_block = self.init_the_blocks("interface")
        for k, v in interface_block.items():
            if k == "options":
                interface_block[k] = self._retrieve_pcapng_function("interface", k)(stream, (self.get_interface_options_size(interface_block['block_len1']) ))
            else:
                interface_block[k] = self._retrieve_pcapng_function("interface", k)(stream)
        # print("Interface", interface_block)
        return interface_block

class Packet(USBParser):
    def __init__(self, filename):
        super().__init__()

        self.pkt = read_file(filename)
        self.is_pcapng = None
        self.pcapng = PCAPng()
        self._headers = {
            "magic_header": None,
        }

        self._pcap_header_fields = {
            "major_version": self.read_word,
            "minor_version": self.read_word,
            "zone_info": self.read_dword,
            "sig_flags": self.read_dword,
            "max_len": self.read_dword,
            "network_type": self.read_dword,
        }

    @staticmethod
    def init_record_fields():
        return {key: None for key in ["timestamp", "time_microseconds", "octet_len", "frame_len", "frame_buff"]}

    def error(self, value):
        raise Exception(f"Pcap is not USB-TYPE. Pcap TYPE :: {NetworkType(value)}")

    def pcap_error(self):
        raise Exception("Invalid Pcap File")

    def _retrieve_pcap_hdr_function(self, method: str):
        return self._pcap_header_fields.get(method)

    def _parse_pcap_header(self, file, sig):
        if sig == PCAPNG_HEADER:
            self.is_pcapng = True
            self._pcap_header_fields = self.pcapng.parse_interface_block(self.pkt)
        else:
            for k, v in self._pcap_header_fields.items():
                self._pcap_header_fields[k] = self._retrieve_pcap_hdr_function(k)(file)
        return self._pcap_header_fields

    def _retrieve_pcap_record_function(self, method: str):
        return self._pcap_record_fields.get(method)

    def _parse_pcap_record(self, file):
        pcap_record = self.init_record_fields()
        for k, v in pcap_record.items():
            if k == "frame_buff":
                pcap_record[k] = self._retrieve_pcap_record_function(k)(file=file,length=pcap_record['frame_len'])
            else:
                pcap_record[k] = self._retrieve_pcap_record_function(k)(file)
        # print(pcap_record)
        return pcap_record

    def _check_valid_usb_pcap(self) -> bool:
        """
        Checks the PCAP Header, also Parse PCAP Headers and checks the USB_PCAP Enum Value
        """
        self._headers['magic_headers'] = self.read_dword(self.pkt)
        # print(hex(self._headers['magic_headers']))
        if self._headers['magic_headers'] == BIG_ENDIAN_PCAP_HEADER or self._headers['magic_headers'] == LITTLE_ENDIAN_PCAP_HEADER:
            return True
        # PCAPNG Headers Metadata
        # https://pcapng.com/
        # Read the 4 bytes and seek it to align the structs
        elif self._headers['magic_headers'] == PCAPNG_HEADER:
            self.pkt.seek(0x0)  # Go back to starting
            return  True
        else:
            self.pcap_error()
            return False

    def get_network_type(self):
        return self._pcap_header_fields['network_type']

    def read_pcap(self):
        if self._check_valid_usb_pcap():
            self._parse_pcap_header(self.pkt, self._headers['magic_headers'])
            # Check the network type is TYPE_USB
            # print("Network Type :: ", NetworkType(self._pcap_header_fields['network_type']))
            # if self._pcap_header_fields['block_type'] == PCAPNG_HEADER:
            #     pass
            # else:
            assert (NetworkType(self._pcap_header_fields['network_type']) == NetworkType(0xf9) or
                    NetworkType(self._pcap_header_fields['network_type']) == NetworkType(0xdc))


    # def __str__(self):
    #     return (f"Headers(\n"
    #             f"Signature={hex(self._headers['magic_headers'])}\n"
    #             f"{self._pcap_header_fields}\n"
    #             f"{self._pcap_record_fields}\n"
    #             f"{self._urb_fields}\n")

