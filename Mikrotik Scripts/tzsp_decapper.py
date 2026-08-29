import socket
import os
import fcntl
import struct
import sys

TUNSETIFF = 0x400454ca
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000

def create_tap(dev="arpa-tap0"):
    try:
        fd = os.open("/dev/net/tun", os.O_RDWR)
        ifr = struct.pack('16sH', dev.encode('utf-8'), IFF_TAP | IFF_NO_PI)
        fcntl.ioctl(fd, TUNSETIFF, ifr)
        os.system(f"ip link set {dev} up")
        return fd
    except PermissionError:
        print("ERROR: Must run as root to create TAP interface.")
        sys.exit(1)

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Increase socket buffer to prevent dropping packets under heavy load
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024 * 16)
    sock.bind(("0.0.0.0", 37008))
    
    tap_fd = create_tap()
    print("Listening for TZSP on UDP 37008. Forwarding decapsulated frames to arpa-tap0...")
    
    while True:
        try:
            data, _ = sock.recvfrom(65535)
            # TZSP Version 1 Check
            if len(data) > 5 and data[0] == 1:
                # Find the End tag (0x01) which signifies end of TZSP header
                idx = 4
                while idx < len(data):
                    if data[idx] == 1: # End tag
                        idx += 1
                        break
                    # TZSP tag format: Type(1 byte), Length(1 byte), Value(Length bytes)
                    tag_type = data[idx]
                    tag_len = data[idx+1]
                    idx += 2 + tag_len
                
                payload = data[idx:]
                if payload:
                    os.write(tap_fd, payload)
        except Exception as e:
            # Catch os.write errors (e.g. interface down) but keep running
            pass

if __name__ == "__main__":
    main()
