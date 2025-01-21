#!/usr/bin/env python3
#Written by Soldier of Fortran (Phil Young) - updated to Python3 by Kev Milne with help of ye old ChatGPT.
"""
tn3270lib.py - Python3 version with cp037 instead of EBCDIC-CP-BE,
and no overshadowing of socket constants.
"""

import sys
import socket
import ssl
import select
import struct
import binascii
import math

# Tunable parameters
DEBUGLEVEL = 0

# Telnet protocol commands as bytes
SE = b"\xf0"    # 240, End of subnegotiation parameters
SB = b"\xfa"    # 250, Sub-option to follow
WILL = b"\xfb"  # 251
WONT = b"\xfc"  # 252
DO = b"\xfd"    # 253
DONT = b"\xfe"  # 254
IAC = b"\xff"   # 255
SEND = b"\x01"  # sub-process negotiation SEND
IS = b"\x00"    # sub-process negotiation IS

# TN3270 Telnet commands
TN_ASSOCIATE = b"\x00"
TN_CONNECT = b"\x01"
TN_DEVICETYPE = b"\x02"
TN_FUNCTIONS = b"\x03"
TN_IS = b"\x04"
TN_REASON = b"\x05"
TN_REJECT = b"\x06"
TN_REQUEST = b"\x07"
TN_RESPONSES = b"\x02"
TN_SEND = b"\x08"
TN_TN3270 = b"\x28"   # 40
TN_EOR = b"\xef"      # 239, End of record in 3270 mode

# Supported Telnet Options
options = {
    "BINARY": b"\x00",
    "EOR": b"\x19",
    "TTYPE": b"\x18",
    "TN3270": b"\x28",
    "TN3270E": b"\x1c",
}

supported_options = {
    b"\x00": "BINARY",
    b"\x19": "EOR",
    b"\x18": "TTYPE",
    b"\x28": "TN3270",
    b"\x1c": "TN3270E",
}

# TN3270 Stream Commands
EAU = b"\x0f"
EW = b"\x05"
EWA = b"\x0d"
RB = b"\x02"
RM = b"\x06"
RMA = b""
W = b"\x01"
WSF = b"\x11"
NOP = b"\x03"
SNS = b"\x04"
SNSID = b"\xe4"

# SNA equivalents
SNA_RMA = b"\x6e"
SNA_EAU = b"\x6f"
SNA_EWA = b"\x7e"
SNA_W = b"\xf1"
SNA_RB = b"\xf2"
SNA_WSF = b"\xf3"
SNA_EW = b"\xf5"
SNA_NOP = b"\x03"
SNA_RM = b"\xf6"

# TN3270 Stream Orders
SF = b"\x1d"
SFE = b"\x29"
SBA = b"\x11"
SA = b"\x28"
MF = b"\x2c"
IC = b"\x13"
PT = b"\x05"
RA = b"\x3c"
EUA = b"\x12"
GE = b"\x08"

# TN3270 Format Control Orders
NUL = b"\x00"
SUB = b"\x3f"
DUP = b"\x1c"
FM = b"\x1e"
FF = b"\x0c"
CR = b"\x0d"
NL = b"\x15"
EM = b"\x19"
EO = b"\xff"  # same as IAC in ASCII?

# TN3270 Attention Identification (AIDS)
NO = b"\x60"
QREPLY = b"\x61"
ENTER = b"\x7d"
PF1 = b"\xf1"
PF2 = b"\xf2"
PF3 = b"\xf3"
PF4 = b"\xf4"
PF5 = b"\xf5"
PF6 = b"\xf6"
PF7 = b"\xf7"
PF8 = b"\xf8"
PF9 = b"\xf9"
PF10 = b"\x7a"
PF11 = b"\x7b"
PF12 = b"\x7c"
PF13 = b"\xc1"
PF14 = b"\xc2"
PF15 = b"\xc3"
PF16 = b"\xc4"
PF17 = b"\xc5"
PF18 = b"\xc6"
PF19 = b"\xc7"
PF20 = b"\xc8"
PF21 = b"\xc9"
PF22 = b"\x4a"
PF23 = b"\x4b"
PF24 = b"\x4c"
OICR = b"\xe6"
MSR_MHS = b"\xe7"
SELECT = b"\x7e"
PA1 = b"\x6c"
PA2 = b"\x6e"
PA3 = b"\x6b"
CLEAR = b"\x6d"
SYSREQ = b"\xf0"

# For Structured Fields
AID_SF = b"\x88"
SFID_QREPLY = b"\x81"

# Code table for addresses
code_table = [
    0x40, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
    0xC8, 0xC9, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
    0x50, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
    0xD8, 0xD9, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
    0x60, 0x61, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,
    0xE8, 0xE9, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
    0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
    0xF8, 0xF9, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
]

# TN3270 data stream flags
NO_OUTPUT = 0
OUTPUT = 1
BAD_COMMAND = 2
BAD_ADDRESS = 3
NO_AID = 0x60

# 3270E
NO_RESPONSE = 0x00
ERROR_RESPONSE = 0x01
ALWAYS_RESPONSE = 0x02
POSITIVE_RESPONSE = 0x00
NEGATIVE_RESPONSE = 0x01

# 3270E data types
DT_3270_DATA = 0x00
DT_SCS_DATA = 0x01
DT_RESPONSE = 0x02
DT_BIND_IMAGE = 0x03
DT_UNBIND = 0x04
DT_NVT_DATA = 0x05
DT_REQUEST = 0x06
DT_SSCP_LU_DATA = 0x07
DT_PRINT_EOJ = 0x08

NEG_COMMAND_REJECT = 0x00
NEG_INTERVENTION_REQUIRED = 0x01
NEG_OPERATION_CHECK = 0x02
NEG_COMPONENT_DISCONNECTED = 0x03

# Structured Fields
SF_READ_PART = b"\x01"
SF_RP_QUERY = b"\x02"
SF_RP_QLIST = b"\x03"
SF_RPQ_LIST = b"\x00"
SF_RPQ_EQUIV = b"\x40"
SF_RPQ_ALL = b"\x80"
SF_ERASE_RESET = b"\x03"
SF_ER_DEFAULT = b"\x00"
SF_ER_ALT = b"\x80"
SF_SET_REPLY_MODE = b"\x09"
SF_SRM_FIELD = b"\x00"
SF_SRM_XFIELD = b"\x01"
SF_SRM_CHAR = b"\x02"
SF_CREATE_PART = b"\x0c"
CPFLAG_PROT = 0x40
CPFLAG_COPY_PS = 0x20
CPFLAG_BASE = 0x07
SF_OUTBOUND_DS = b"\x40"
SF_TRANSFER_DATA = b"\xd0"

# File Transfer (IND$FILE) constants
TR_OPEN_REQ = 0x0012
TR_CLOSE_REQ = 0x4112
TR_SET_CUR_REQ = 0x4511
TR_GET_REQ = 0x4611
TR_INSERT_REQ = 0x4711
TR_DATA_INSERT = 0x4704

TR_GET_REPLY = 0x4605
TR_NORMAL_REPLY = 0x4705
TR_ERROR_REPLY = 0x08
TR_CLOSE_REPLY = 0x4109

TR_RECNUM_HDR = 0x6306
TR_ERROR_HDR = 0x6904
TR_NOT_COMPRESSED = 0xc080
TR_BEGIN_DATA = 0x61

TR_ERR_EOF = 0x2200
TR_ERR_CMDFAIL = 0x0100

DFT_BUF = 4096
DFT_MIN_BUF = 256
DFT_MAX_BUF = 32768

FT_NONE = 1
FT_AWAIT_ACK = 2

# 3270E negotiation
TN3270E_ASSOCIATE = b"\x00"
TN3270E_CONNECT = b"\x01"
TN3270E_DEVICE_TYPE = b"\x02"
TN3270E_FUNCTIONS = b"\x03"
TN3270E_IS = b"\x04"
TN3270E_REASON = b"\x05"
TN3270E_REJECT = b"\x06"
TN3270E_REQUEST = b"\x07"
TN3270E_SEND = b"\x08"

NEGOTIATING = 0
CONNECTED = 1
TN3270_DATA = 2
TN3270E_DATA = 3

DEVICE_TYPE = "IBM-3279-2-E"
COLS = 80
ROWS = 24
WORD_STATE = ["Negotiating", "Connected", "TN3270 mode", "TN3270E mode"]
TELNET_PORT = 23

telnet_commands = {
    SE: "SE",
    SB: "SB",
    WILL: "WILL",
    WONT: "WONT",
    DO: "DO",
    DONT: "DONT",
    IAC: "IAC",
    SEND: "SEND",
    IS: "IS",
}

telnet_options = {
    TN_ASSOCIATE: "ASSOCIATE",
    TN_CONNECT: "CONNECT",
    TN_DEVICETYPE: "DEVICE_TYPE",
    TN_FUNCTIONS: "FUNCTIONS",
    TN_IS: "IS",
    TN_REASON: "REASON",
    TN_REJECT: "REJECT",
    TN_REQUEST: "REQUEST",
    TN_RESPONSES: "RESPONSES",
    TN_SEND: "SEND",
    TN_TN3270: "TN3270",
    TN_EOR: "EOR",
}

tn3270_options = {
    TN3270E_ASSOCIATE: "TN3270E_ASSOCIATE",
    TN3270E_CONNECT: "TN3270E_CONNECT",
    TN3270E_DEVICE_TYPE: "TN3270E_DEVICE_TYPE",
    TN3270E_FUNCTIONS: "TN3270E_FUNCTIONS",
    TN3270E_IS: "TN3270E_IS",
    TN3270E_REASON: "TN3270E_REASON",
    TN3270E_REJECT: "TN3270E_REJECT",
    TN3270E_REQUEST: "TN3270E_REQUEST",
    TN3270E_SEND: "TN3270E_SEND",
}


class TN3270:
    def __init__(self, host=None, port=0, timeout=10):
        self.debuglevel = DEBUGLEVEL
        self.host = host
        self.port = port
        self.timeout = timeout
        self.eof = False
        self.sock = None
        self._has_poll = hasattr(select, "poll")
        self.unsupported_opts = {}
        self.telnet_state = 0
        self.server_options = {}
        self.client_options = {}
        self.sb_options = b""
        self.connected_lu = ""
        self.connected_dtype = ""
        self.first_screen = False
        self.aid = NO
        self.telnet_data = b""
        self.tn_buffer = b""
        self.raw_tn = []
        self.state = 0
        self.buffer_address = 0
        self.formatted = False

        self.buffer = []
        self.fa_buffer = []
        self.overwrite_buf = []
        self.cursor_addr = 0
        self.header_sequence = 0
        self.tn3270_header = {
            "data_type": None,
            "request_flag": None,
            "response_flag": None,
            "seq_number": None,
        }

        self.ft_buffersize = 0
        self.ft_state = FT_NONE
        self.ascii_file = False
        self.file = None
        self.filename = None
        self.ssl = False

        if host is not None:
            self.initiate(host, port, timeout)

    def __del__(self):
        self.disconnect()

    def msg(self, level, msg, *args):
        if self.debuglevel >= level:
            print(f"TN3270({self.host},{self.port}): ", end="")
            if args:
                print(msg % args)
            else:
                print(msg)

    def set_debuglevel(self, debuglevel=1):
        self.debuglevel = debuglevel

    def set_LU(self, LU):
        self.connected_lu = LU

    def disable_enhanced(self, disable=True):
        self.msg(1, "Disabling TN3270E Option")
        if disable:
            self.unsupported_opts[b"\x28"] = "TN3270"
        else:
            self.unsupported_opts.pop(b"\x28", None)

    def disconnect(self):
        if self.sock:
            self.sock.close()
            self.sock = None

    def get_socket(self):
        return self.sock

    def send_data(self, data: bytes):
        if self.debuglevel >= 2:
            print(f"send {data!r}")
        self.sock.sendall(data)

    def recv_data(self) -> bytes:
        if self.debuglevel >= 2:
            print("Receiving Data (up to 256 bytes).")
        buf = self.sock.recv(256)
        if self.debuglevel >= 2:
            print(f"Received Data: {buf!r}")
        return buf

    def DECODE_BADDR(self, byte1, byte2) -> int:
        """Decode 2 bytes as a 3270 buffer address (14-bit)."""
        if (byte1 & 0xC0) == 0:
            return ((byte1 & 0x3F) << 8) | byte2
        else:
            return ((byte1 & 0x3F) << 6) | (byte2 & 0x3F)

    def ENCODE_BADDR(self, address: int) -> bytes:
        """Encode a 14-bit buffer address into 2 EBCDIC bytes, using code_table."""
        b1 = code_table[(address >> 6) & 0x3F]
        b2 = code_table[address & 0x3F]
        return bytes([b1]) + bytes([b2])

    def BA_TO_ROW(self, addr: int) -> int:
        return int(math.ceil((addr / COLS) + 0.5))

    def BA_TO_COL(self, addr: int) -> int:
        return addr % COLS

    def INC_BUF_ADDR(self, addr: int) -> int:
        return (addr + 1) % (COLS * ROWS)

    def DEC_BUF_ADDR(self, addr: int) -> int:
        return (addr - 1) % (COLS * ROWS)

    def check_tn3270(self, host, port=0, timeout=3) -> bool:
        if not port:
            port = TELNET_PORT
        try:
            plain = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ssl_sock = ssl.wrap_socket(plain, cert_reqs=ssl.CERT_NONE)
            ssl_sock.settimeout(timeout)
            ssl_sock.connect((host, port))
            sock = ssl_sock
        except ssl.SSLError:
            plain.close()
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect((host, port))
            except Exception as e:
                self.msg(1, "Error: %r", e)
                return False
        except Exception as e:
            self.msg(1, "Error: %r", e)
            return False

        data = sock.recv(256)
        if data == IAC + DO + options["TN3270"]:
            sock.close()
            return True
        elif data == IAC + DO + options["TTYPE"]:
            sock.sendall(IAC + WILL + options["TTYPE"])
            data = sock.recv(256)
            if data != IAC + SB + options["TTYPE"] + SEND + IAC + SE or data == b"":
                sock.close()
                return False
            sock.sendall(IAC + SB + options["TTYPE"] + IS + DEVICE_TYPE.encode("ascii") + IAC + SE)
            data = sock.recv(256)
            if data.startswith(IAC + DO):
                sock.close()
                return True
        sock.close()
        return False

    def connect(self, host, port=0, timeout=30) -> bool:
        if not port:
            port = TELNET_PORT
        self.host = host
        self.port = port
        self.timeout = timeout

        try:
            self.msg(1, "Trying SSL/TLS to %s:%d", self.host, self.port)
            plain = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ssl_sock = ssl.wrap_socket(plain, cert_reqs=ssl.CERT_NONE)
            ssl_sock.settimeout(timeout)
            ssl_sock.connect((host, port))
            self.sock = ssl_sock
            self.ssl = True
        except (ssl.SSLError, socket.error) as e:
            self.msg(1, "SSL/TLS Failed. Trying Plaintext. Error: %r", e)
            try:
                if plain:
                    plain.close()
            except:
                pass
            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.settimeout(timeout)
                self.sock.connect((host, port))
            except Exception as e2:
                self.msg(1, "Error: %r", e2)
                return False
        except Exception as e:
            self.msg(1, "[SSL] Generic Error: %r", e)
            return False
        return True

    def initiate(self, host, port=0, timeout=5) -> bool:
        if not self.connect(host, port, timeout):
            return False

        self.client_options = {}
        self.server_options = {}
        self.state = NEGOTIATING
        self.first_screen = False

        while not self.first_screen:
            try:
                self.telnet_data = self.recv_data()
                if not self.telnet_data:
                    break
                if not self.process_packets():
                    return False
            except socket.timeout as e:
                self.msg(1, "Timeout in initiate: %r", e)
                break
            except socket.error as e:
                self.msg(1, "Socket Error: %r", e)
                break
        return True

    def get_data(self):
        self.first_screen = False
        while not self.first_screen:
            try:
                self.telnet_data = self.recv_data()
                if not self.telnet_data:
                    break
                self.process_packets()
            except socket.timeout as e:
                self.msg(1, "recv timed out in get_data: %r", e)
                break
            except socket.error as e:
                self.msg(1, "Socket Error in get_data: %r", e)
                break

    def get_all_data(self):
        self.first_screen = False
        self.sock.settimeout(2)
        count = 0
        while True and count <= 200:
            try:
                chunk = self.recv_data()
                if chunk:
                    self.telnet_data = chunk
                    self.msg(1, "Recv'd %d bytes", len(chunk))
                    self.process_packets()
                else:
                    count += 1
            except socket.timeout as e:
                self.msg(1, "recv timed out in get_all_data: %r", e)
                break
            except socket.error as e:
                self.msg(1, "Error Received: %r", e)
                break
        self.sock.settimeout(None)

    def process_packets(self) -> bool:
        for i in self.telnet_data:
            c = bytes([i])
            if not self.ts_processor(c):
                return False
        self.telnet_data = b""
        return True

    def ts_processor(self, data: bytes) -> bool:
        TNS_DATA = 0
        TNS_IAC = 1
        TNS_WILL = 2
        TNS_WONT = 3
        TNS_DO = 4
        TNS_DONT = 5
        TNS_SB = 6
        TNS_SB_IAC = 7

        DO_reply = IAC + DO
        DONT_reply = IAC + DONT
        WILL_reply = IAC + WILL
        WONT_reply = IAC + WONT

        if self.telnet_state == TNS_DATA:
            if data == IAC:
                self.telnet_state = TNS_IAC
            else:
                self.store3270(data)
        elif self.telnet_state == TNS_IAC:
            if data == IAC:
                self.store3270(data)
                self.telnet_state = TNS_DATA
            elif data == TN_EOR:
                if self.state in [TN3270_DATA, TN3270E_DATA]:
                    self.process_data()
                self.telnet_state = TNS_DATA
            elif data == WILL:
                self.telnet_state = TNS_WILL
            elif data == WONT:
                self.telnet_state = TNS_WONT
            elif data == DO:
                self.telnet_state = TNS_DO
            elif data == DONT:
                self.telnet_state = TNS_DONT
            elif data == SB:
                self.telnet_state = TNS_SB
                self.sb_options = b""
        elif self.telnet_state == TNS_WILL:
            if data in supported_options and data not in self.unsupported_opts:
                self.msg(1, f"<< IAC WILL {supported_options[data]}")
                if not self.server_options.get(data, False):
                    self.server_options[data] = True
                    self.send_data(DO_reply + data)
                    self.msg(1, f">> IAC DO {supported_options[data]}")
                    self.in3270()
            else:
                self.send_data(DONT_reply + data)
                self.msg(1, f">> IAC DONT {data}")
            self.telnet_state = TNS_DATA
        elif self.telnet_state == TNS_WONT:
            if self.server_options.get(data, False):
                self.server_options[data] = False
                self.send_data(DONT_reply + data)
                self.msg(1, f"Sent WONT Reply {data}")
                self.in3270()
            self.telnet_state = TNS_DATA
        elif self.telnet_state == TNS_DO:
            if data in supported_options and data not in self.unsupported_opts:
                self.msg(1, f"<< IAC DO {supported_options[data]}")
                if not self.client_options.get(data, False):
                    self.client_options[data] = True
                    self.send_data(WILL_reply + data)
                    self.msg(1, f">> IAC WILL {supported_options[data]}")
                    self.in3270()
            else:
                self.send_data(WONT_reply + data)
                self.msg(1, f"Unsupported 'DO': {data!r}")
            self.telnet_state = TNS_DATA
        elif self.telnet_state == TNS_DONT:
            if self.client_options.get(data, False):
                self.client_options[data] = False
                self.send_data(WONT_reply + data)
                self.msg(1, f">> IAC DONT {data}")
                self.in3270()
            self.telnet_state = TNS_DATA
        elif self.telnet_state == TNS_SB:
            if data == IAC:
                self.telnet_state = TNS_SB_IAC
            else:
                self.sb_options += data
        elif self.telnet_state == TNS_SB_IAC:
            self.sb_options += data
            if data == SE:
                self.telnet_state = TNS_DATA
                if self.state != TN3270E_DATA:
                    pass
                if (
                    self.sb_options.startswith(options["TTYPE"])
                    and self.sb_options.endswith(SEND + IAC + SE)
                ):
                    self.msg(1, ">> IAC SB TTYPE IS DEVICE_TYPE IAC SE")
                    self.send_data(
                        IAC + SB + options["TTYPE"] + IS + DEVICE_TYPE.encode("ascii") + IAC + SE
                    )
                elif (
                    self.client_options.get(options["TN3270"], False)
                    and self.sb_options.startswith(options["TN3270"])
                ):
                    if not self.negotiate_tn3270():
                        return False
        return True

    def negotiate_tn3270(self) -> bool:
        if len(self.sb_options) < 3:
            return True
        # minimal placeholder
        return True

    def store3270(self, ch: bytes):
        self.tn_buffer += ch

    def process_data(self):
        if self.state == TN3270E_DATA:
            if len(self.tn_buffer) < 5:
                return
            self.tn3270_header["data_type"] = self.tn_buffer[0]
            self.tn3270_header["request_flag"] = self.tn_buffer[1]
            self.tn3270_header["response_flag"] = self.tn_buffer[2]
            self.tn3270_header["seq_number"] = self.tn_buffer[3:5]
            if self.tn3270_header["data_type"] == 0x00:
                self.process_3270(self.tn_buffer[5:])
                self.raw_tn.append(self.tn_buffer[5:])
        else:
            self.process_3270(self.tn_buffer)
            self.raw_tn.append(self.tn_buffer)
        self.tn_buffer = b""

    def in3270(self):
        if self.client_options.get(options["TN3270"], False):
            self.state = TN3270E_DATA
        elif (
            self.server_options.get(options["EOR"], False)
            and self.server_options.get(options["BINARY"], False)
            and self.client_options.get(options["BINARY"], False)
            and self.client_options.get(options["TTYPE"], False)
        ):
            self.state = TN3270_DATA
        if self.state in [TN3270_DATA, TN3270E_DATA]:
            self.msg(1, "Entering TN3270 Mode:")
            self.buffer = [b"\x00"] * 1920
            self.fa_buffer = [b"\x00"] * 1920
            self.overwrite_buf = [b"\x00"] * 1920
            self.msg(1, "Created buffers of length 1920")
        self.msg(1, f"Current State: {WORD_STATE[self.state]}")

    def clear_screen(self):
        self.buffer_address = 0
        self.buffer = [b"\x00"] * 1920
        self.fa_buffer = [b"\x00"] * 1920
        self.overwrite_buf = [b"\x00"] * 1920

    def clear_unprotected(self):
        pass

    def process_3270(self, data: bytes):
        if not data:
            return
        com = data[0:1]
        if com in [EAU, SNA_EAU]:
            self.msg(1, "TN3270 Command: Erase All Unprotected")
            self.clear_unprotected()
        elif com in [EWA, SNA_EWA, EW, SNA_EW]:
            self.msg(1, "TN3270 Command: Erase/Write(Alt)")
            self.clear_screen()
            self.process_write(data)
        elif com in [W, SNA_W]:
            self.msg(1, "TN3270 Command: Write")
            self.process_write(data)
        elif com in [RB, SNA_RB]:
            self.msg(1, "TN3270 Command: Read Buffer")
            self.process_read()
        elif com in [RM, SNA_RM]:
            self.msg(1, "TN3270 Command: Read Modified")
            self.process_read_modified(self.aid)
        elif com in [WSF, SNA_WSF]:
            self.msg(1, "TN3270 Command: Write Structured Field")
            self.w_structured_field(data)
        elif com in [NOP, SNA_NOP]:
            self.msg(1, "TN3270 Command: NOP")
        else:
            self.msg(1, f"Unknown 3270 Data Stream command: {com!r}")

    def process_write(self, data: bytes):
        if len(data) < 2:
            return
        wcc = data[1]
        i = 2
        self.buffer_address = 0
        if (wcc & 0x40):
            self.msg(2, "WCC Reset")
        if (wcc & 0x02):
            self.msg(2, "WCC Restore")

        while i < len(data):
            cp = data[i : i + 1]
            if cp == SF:
                i += 1
                if i < len(data):
                    attr = data[i : i + 1]
                    self.write_char(b"\x00")
                    self.buffer_address = self.INC_BUF_ADDR(self.buffer_address)
                    self.write_field_attribute(attr)
                    i += 1
            elif cp == SFE:
                i += 1
                if i < len(data):
                    num_attr = data[i]
                    i += 1
                    for _ in range(num_attr):
                        i += 2
                self.buffer_address = self.INC_BUF_ADDR(self.buffer_address)
            elif cp == SBA:
                i += 1
                if i + 1 < len(data):
                    b1 = data[i]
                    b2 = data[i + 1]
                    self.buffer_address = self.DECODE_BADDR(b1, b2)
                    i += 2
            elif cp == IC:
                self.msg(1, "Insert Cursor")
                self.cursor_addr = self.buffer_address
                i += 1
            elif cp == RA:
                i += 1
                if i + 1 < len(data):
                    b1 = data[i]
                    b2 = data[i + 1]
                    i += 2
                    ra_baddr = self.DECODE_BADDR(b1, b2)
                    if i < len(data):
                        char_to_repeat = data[i : i + 1]
                        i += 1
                        while self.buffer_address != ra_baddr:
                            self.write_char(char_to_repeat)
                            self.buffer_address = self.INC_BUF_ADDR(self.buffer_address)
            elif cp == EUA:
                i += 1
                if i + 1 < len(data):
                    b1 = data[i]
                    b2 = data[i + 1]
                    i += 2
                    eua_baddr = self.DECODE_BADDR(b1, b2)
                    while self.buffer_address != eua_baddr:
                        self.buffer_address = self.INC_BUF_ADDR(self.buffer_address)
            elif cp == GE:
                i += 1
                if i < len(data):
                    ge_char = data[i : i + 1]
                    self.write_char(ge_char)
                    self.buffer_address = self.INC_BUF_ADDR(self.buffer_address)
                    i += 1
            elif cp == MF:
                i += 1
                if i < len(data):
                    num_attr = data[i]
                    i += 1 + num_attr
                self.buffer_address = self.INC_BUF_ADDR(self.buffer_address)
            elif cp == SA:
                i += 2
            elif cp in [NUL, SUB, DUP, FM, FF, CR, NL, EM, EO]:
                self.write_char(b"\x40")
                self.buffer_address = self.INC_BUF_ADDR(self.buffer_address)
                i += 1
            else:
                self.write_char(cp)
                self.buffer_address = self.INC_BUF_ADDR(self.buffer_address)
                if not self.first_screen:
                    self.first_screen = True
                i += 1

    def write_char(self, char: bytes):
        if self.buffer[self.buffer_address] == b"\x00":
            self.buffer[self.buffer_address] = char
        else:
            self.overwrite_buf[self.buffer_address] = self.buffer[self.buffer_address]
            self.buffer[self.buffer_address] = char

    def write_field_attribute(self, attr: bytes):
        self.fa_buffer[self.buffer_address - 1] = attr

    def process_read(self):
        self.msg(1, "Generating Read Buffer")
        self.output_buffer = []
        self.output_buffer.append(self.aid)
        self.output_buffer.append(self.ENCODE_BADDR(self.cursor_addr))
        self.send_tn3270(self.output_buffer)

    def process_read_modified(self, aid):
        self.msg(1, "Generating Read Modified buffer")
        self.output_buffer = []
        self.output_buffer.append(self.aid)
        self.output_buffer.append(self.ENCODE_BADDR(self.cursor_addr))
        self.send_tn3270(self.output_buffer)

    def send_tn3270(self, data_list):
        packet = b""
        if self.state == TN3270E_DATA:
            packet = b"\x00\x00\x00\x00\x00"
        for item in data_list:
            packet += item
        if IAC in packet:
            packet = packet.replace(IAC, IAC + IAC)
        packet += IAC + TN_EOR
        self.send_data(packet)

    def w_structured_field(self, wsf_data: bytes):
        wsf_cmd = wsf_data[1:]
        bufflen = len(wsf_cmd)
        if bufflen < 2:
            self.msg(1, "WSF too short")
            return
        while bufflen > 0:
            if bufflen < 2:
                self.msg(1, "WSF loop length <2")
                return
            fieldlen = (wsf_cmd[0] << 8) + wsf_cmd[1]
            if fieldlen == 0:
                fieldlen = bufflen
            if fieldlen < 3:
                self.msg(1, f"error: field length {fieldlen} too small")
                return
            if fieldlen > bufflen:
                self.msg(1, f"error: field length {fieldlen} > buffer length {bufflen}")
                return

            subdata = wsf_cmd[:fieldlen]
            sfid = subdata[2:3]
            if sfid == SF_READ_PART:
                self.msg(1, "[WSF] Read Partition")
                self.read_partition(subdata[3:fieldlen])
            elif sfid == SF_ERASE_RESET:
                self.msg(1, "[WSF] Erase Reset")
                self.erase_reset(subdata[3:fieldlen])
            elif sfid == SF_SET_REPLY_MODE:
                self.msg(1, "[WSF] Set Reply Mode")
            elif sfid == SF_CREATE_PART:
                self.msg(1, "[WSF] Create Partition")
            elif sfid == SF_OUTBOUND_DS:
                self.msg(1, "[WSF] Outbound DS")
                self.outbound_ds(subdata[3:fieldlen])
            elif sfid == SF_TRANSFER_DATA:
                self.msg(1, "[WSF] File Transfer Data")
                self.file_transfer(subdata)
            else:
                self.msg(1, f"[WSF] unsupported ID: {sfid!r}")

            wsf_cmd = wsf_cmd[fieldlen:]
            bufflen -= fieldlen

    def read_partition(self, data: bytes):
        if not data:
            return
        part_id = data[0]
        if len(data) < 2:
            return
        if data[1:2] == SF_RP_QUERY:
            self.msg(1, "Read Partition Query")
            if part_id != 0xFF:
                return
            query_opts = binascii.unhexlify(
                "88000e81808081848586878895a1a60017818101000050001801000a0"
                "2e50002006f090c07800008818400078000001b81858200090c000000"
                "000700100002b900250110f103c3013600268186001000f4f1f1f2f2f"
                "3f3f4f4f5f5f6f6f7f7f8f8f9f9fafafbfbfcfcfdfdfefeffffffff00"
                "0f81870500f0f1f1f2f2f4f4f8f800078188000102000c81950000100"
                "010000101001281a1000000000000000006a3f3f2f7f0001181a6000"
                "00b01000050001800500018ffef"
            )
            if self.state == TN3270E_DATA:
                query_opts = b"\x00\x00\x00\x00\x00" + query_opts
            self.send_data(query_opts)

    def outbound_ds(self, data: bytes):
        if len(data) < 2:
            return
        if data[1:2] == SNA_W:
            self.msg(1, "   - Write")
            self.process_write(data[1:])
        elif data[1:2] == SNA_EW:
            self.msg(1, "   - Erase/Write")
            self.clear_screen()
            self.process_write(data[1:])
        elif data[1:2] == SNA_EWA:
            self.msg(1, "   - Erase/Write/Alternate")
            self.clear_screen()
            self.process_write(data[1:])
        elif data[1:2] == SNA_EAU:
            self.msg(1, "   - Erase All Unprotected")
            self.clear_unprotected()

    def erase_reset(self, data: bytes):
        if len(data) >= 2 and data[1:2] in [SF_ER_DEFAULT, SF_ER_ALT]:
            self.clear_screen()

    def file_transfer(self, data: bytes):
        if self.ft_state == FT_NONE:
            return
        # minimal stub

    def send_cursor(self, text: str):
        """
        Send 'text' from current cursor, then press ENTER.
        Encode text to cp037.
        """
        output_buffer = []
        output_buffer.append(ENTER)
        output_buffer.append(self.ENCODE_BADDR(self.cursor_addr))
        output_buffer.append(SBA)
        output_buffer.append(self.ENCODE_BADDR(self.cursor_addr))
        for ch in text:
            eb = ch.encode("cp037", errors="replace")
            output_buffer.append(eb)
        self.send_tn3270(output_buffer)

    def send_pf(self, pf: int) -> bool:
        if pf < 1 or pf > 24:
            self.msg(1, f"PF must be 1..24, got {pf}")
            return False
        name = f"PF{pf}"
        if name in globals():
            val = globals()[name]
        else:
            self.msg(1, f"PF name not found: {name}")
            return False
        output_buffer = [val, self.ENCODE_BADDR(self.cursor_addr)]
        self.send_tn3270(output_buffer)
        return True

    def send_enter(self):
        output_buffer = [ENTER, self.ENCODE_BADDR(self.cursor_addr)]
        self.send_tn3270(output_buffer)
        return True

    def hexdump(self, src: bytes, length=8) -> str:
        result = []
        for i in range(0, len(src), length):
            chunk = src[i : i + length]
            hexa = " ".join(f"{c:02X}" for c in chunk)
            text = "".join(chr(c) if 0x20 <= c < 0x7F else "." for c in chunk)
            result.append(f"{i:04X}   {hexa:<{length*3}}   {text}")
        return "\n".join(result)

    def raw_screen_buffer(self):
        return self.raw_tn

    def writeable(self):
        wlist = []
        b_loc = 0
        while b_loc < len(self.fa_buffer):
            fattr = self.fa_buffer[b_loc]
            if fattr != b"\x00" and not (fattr[0] & 0x20):
                j_loc = 0
                sub_i = b_loc + 1
                while sub_i < len(self.fa_buffer):
                    if self.fa_buffer[sub_i] != b"\x00" and (self.fa_buffer[sub_i][0] & 0x20):
                        break
                    sub_i += 1
                    j_loc += 1
                wlist.append((b_loc + 1, b_loc + 1 + j_loc))
            b_loc += 1
        return wlist

    def is_ssl(self) -> bool:
        return self.ssl


def test():
    import sys
    debuglevel = 0
    argv = sys.argv[:]
    while len(argv) > 1 and argv[1] == "-d":
        debuglevel += 1
        del argv[1]
    host = "localhost"
    port = 23
    if len(argv) > 1:
        host = argv[1]
    if len(argv) > 2:
        port = int(argv[2])
    tn = TN3270()
    tn.set_debuglevel(debuglevel)
    ok = tn.initiate(host, port)
    if ok:
        tn.print_screen()
        tn.disconnect()


if __name__ == "__main__":
    test()
