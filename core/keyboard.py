from core.usbutils import *
from core.transfer_type import  *
from enum import Enum

class USBDeviceType(Enum):
    KEYBOARD=0x0
    MOUSE=0x1

class KeyMapping:
    usb_codes = {
        "0x04": ['a', 'A'], "0x05": ['b', 'B'], "0x06": ['c', 'C'], "0x07": ['d', 'D'], "0x08": ['e', 'E'],
        "0x09": ['f', 'F'], "0x0A": ['g', 'G'], "0x0B": ['h', 'H'], "0x0C": ['i', 'I'], "0x0D": ['j', 'J'],
        "0x0E": ['k', 'K'], "0x0F": ['l', 'L'], "0x10": ['m', 'M'], "0x11": ['n', 'N'], "0x12": ['o', 'O'],
        "0x13": ['p', 'P'], "0x14": ['q', 'Q'], "0x15": ['r', 'R'], "0x16": ['s', 'S'], "0x17": ['t', 'T'],
        "0x18": ['u', 'U'], "0x19": ['v', 'V'], "0x1A": ['w', 'W'], "0x1B": ['x', 'X'], "0x1C": ['y', 'Y'],
        "0x1D": ['z', 'Z'], "0x1E": ['1', '!'], "0x1F": ['2', '@'], "0x20": ['3', '#'], "0x21": ['4', '$'],
        "0x22": ['5', '%'], "0x23": ['6', '^'], "0x24": ['7', '&'], "0x25": ['8', '*'], "0x26": ['9', '('],
        "0x27": ['0', ')'], "0x28": ['\n', '\n'], "0x29": ['[ESC]', '[ESC]'], "0x2A": ['[BACKSPACE]', '[BACKSPACE]'],
        "0x2B": ['\t', '\t'], "0x2C": [' ', ' '], "0x2D": ['-', '_'], "0x2E": ['=', '+'], "0x2F": ['[', '{'],
        "0x30": [']', '}'], "0x31": ['\',"|'], "0x32": ['#', '~'], "0x33": ";:", "0x34": "'\"", "0x36": ",<",
        "0x37": ".>", "0x38": "/?", "0x39": ['[CAPSLOCK]', '[CAPSLOCK]'], "0x3A": ['F1'], "0x3B": ['F2'],
        "0x3C": ['F3'], "0x3D": ['F4'], "0x3E": ['F5'], "0x3F": ['F6'], "0x41": ['F7'], "0x42": ['F8'], "0x43": ['F9'],
        "0x44": ['F10'], "0x45": ['F11'], "0x46": ['F12'], "0x4F": [u'→', u'→'], "0x50": [u'←', u'←'],
        "0x51": [u'↓', u'↓'], "0x52": [u'↑', u'↑']
}

class Result(KeyMapping):
    def __init__(self):
        self.devices = dict()
        self.type = None

    def register_new_device(self, ip):
        self.devices[ip] = list()

    @staticmethod
    def _special_keypress(val):
        if val[0x0] == 0x20 or  val[0x0] == 0x02:
            return True
        else:
            return False

    def _decode_the_strokes(self, val, _id):
        tmp = self.usb_codes.get(
            "0x" + str(hex(val[0x2]))[2:].zfill(2).upper()
        )
        if tmp is not None:
            if tmp[0] == self.usb_codes.get('0x2A')[0]:
                # print(self.devices[_id])
                self.devices[_id].pop( )  # Remove if backspace is pressed
                return None
            if self._special_keypress(val):
                return tmp[1]
            else: return tmp[0]
        else: return None

    def push_result(self, out):
        if out['id'] not in self.devices:
            self.register_new_device(out['id'])
        tmp = self._decode_the_strokes(out['data'], out['id'])
        if tmp is not None:
            self.devices[out['id']].append(tmp)

    def dump_result(self):
        return self.devices
        # result = ""
        # for _, val in self.devices.items():
        #     result += (''.join(val))
        # return _, result

class USBKeyboard(Packet, PCAPng):
    def __init__(self, filename):
        super().__init__(filename)
        self.enhanced_packet_block = None
        self.urb_fields = None
        self.linux_mapped_urb_fields = None
        self.pcap_record_fields = None
        self.result = Result()

    def _is_towards_host(self):
        q_value = self.urb_fields.get('urb_type')
        if q_value is not None:
            return True if URBType(q_value) == URBType(0x43) else False
        q_value = self.urb_fields.get('irp_info')
        if q_value is not None:
            return True if q_value == 1 else False

    def _is_urb_interrupt(self):
        # print("URB TRANSFER TYPE :: ", self.urb_fields['urb_transfer_type'])
        if URBTransferType(self.urb_fields['urb_transfer_type']) == URBTransferType(0x1):
            return True
        return False

    def _is_urb_bulk_interrupt(self):
        if ((URBFunction(self.urb_fields['urb_function']) == URBFunction(0x9) ) or
                (URBFunction(self.urb_fields['urb_function']) == URBFunction(0x37) )):
            return True
        return False

    def is_eof(self):
        return True if self.pcap_record_fields['frame_len'] == 0x0 else False

    def is_interrupt(self):
        return self._is_urb_interrupt()

    def _process_parsing(self):
        if NetworkType(self.get_network_type()) == NetworkType(0xdc):
            # NOTE: Assign to pcap_record_fields to avoid multiple checks
            if self.is_pcapng:
                return   self._parse_linux_mapped_urb_fields(self.enhanced_packet_block["frame_buff"])
            else: return self._parse_linux_mapped_urb_fields(self.pcap_record_fields['frame_buff'])
        # TODO: Abstract it
        elif NetworkType(self.get_network_type()) == NetworkType(0xf9):
            if self.is_pcapng:
                  return  self.read_usb(self.enhanced_packet_block["frame_buff"])
            else: return  self.read_usb(self.pcap_record_fields['frame_buff'])

    def _check_network_type(self):
        if self.is_pcapng:
            if NetworkType(self.get_network_type()) == NetworkType(0xdc):
                return self.parse_enhanced_block(self.pkt)
            elif NetworkType(self.get_network_type()) == NetworkType(0xf9):
                # return self.read_usb(self.parse_enhanced_block(self.pkt))
                return self.parse_enhanced_block(self.pkt)

        # Parses the PCAP structure !!
        # if NetworkType(self.get_network_type()) == NetworkType(0xdc):
        #     return self._parse_linux_mapped_urb_fields(self.pcap_record_fields['frame_buff'])
        # # TODO: Abstract it
        # elif NetworkType(self.get_network_type()) == NetworkType(0xf9):
        #     return  self.read_usb(self.pcap_record_fields['frame_buff'])
        return self._process_parsing()

    def decode_pcapng(self):
        while True:
            self.enhanced_packet_block = self._check_network_type()
            if self.enhanced_packet_block is None: # Marks end
                break
            self.urb_fields = self._process_parsing()
            if self.urb_fields is None: continue
            if self.is_interrupt() and self._is_towards_host() and len(self.urb_fields.get('pkt_data')) ==0x8:
                # print(self.urb_fields['pkt_data'])
                self.result.push_result(
                    out={"id": self.urb_fields['pseudo_ip'], "data": self.urb_fields['pkt_data']}
                )


    def decode_pcap(self):
        while True:
            self.pcap_record_fields = self._parse_pcap_record(self.pkt)
            if self.is_eof():
                break

            self.urb_fields = self._check_network_type()
            # When frame is either CONTROL or ISO CHRONOUS, returns None
            if self.urb_fields is None:
                # skipped the current frame
                continue

            # TODO: AVOID CHECK ON DATA LENGTH
            if self.is_interrupt() and self._is_towards_host() and len(self.urb_fields.get('pkt_data')) ==0x8:
                # print(self.urb_fields['pkt_data'])
                self.result.push_result(
                    out={"id": self.urb_fields['pseudo_ip'], "data": self.urb_fields['pkt_data']}
                )

    def decode(self):
            self.read_pcap()
            if self.is_pcapng:
                self.decode_pcapng()
            else:
                self.decode_pcap()

            # # When frame is either CONTROL or ISO CHRONOUS, returns None
            # if self.urb_fields is None:
            #     # skipped the current frame
            #     continue
            #
            # # TODO: AVOID CHECK ON DATA LENGTH
            # if self.is_interrupt() and self._is_towards_host() and len(self.urb_fields.get('pkt_data')) ==0x8:
            #     # print(self.urb_fields['pkt_data'])
            #     self.result.push_result(
            #         out={"id": self.urb_fields['pseudo_ip'], "data": self.urb_fields['pkt_data']}
            #     )
            return self.result.dump_result()

