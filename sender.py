from socket import *
import struct
import time
import random

# Packet structure
class Packet:
    def __init__(self, seq, flags, ack, payload, rwnd=0):
        self.seq = seq
        self.flags = flags
        self.ack = ack
        self.payload = payload
        self.rwnd = rwnd

    def pack(self):
        header = struct.pack("IIIB", self.seq, self.ack, self.rwnd, self.flags)
        pb = self.payload.encode()
        length = struct.pack("I", len(pb))
        return header + length + pb

    @staticmethod
    def unpack(b):
        seq, ack, rwnd, flags = struct.unpack("IIIB", b[:13])
        length = struct.unpack("I", b[13:17])[0]
        payload = b[17:17+length].decode()
        return Packet(seq, flags, ack, payload, rwnd)

#  Handshake function
def handshake():
    pass

#  Main send loop
def send_file():
    pass


if __name__ == "__main__":
    if handshake():
        send_file()
