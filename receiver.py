from socket import *
import struct
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


FLAG_SYN = 0b001
FLAG_ACK = 0b010

receiver_socket = socket(AF_INET, SOCK_DGRAM)
receiver_socket.bind(("", 1200))
receiver_socket.settimeout(20)

# Handshake
def do_handshake():
    print("Receiver: Waiting for SYN...")

    try:
        data, addr = receiver_socket.recvfrom(2048)
    except timeout:
        print("Receiver: No SYN received.")
        return False, None

    syn = Packet.unpack(data)
    if not (syn.flags & FLAG_SYN):
        print("Receiver: Packet was not SYN.")
        return False, None

    print("Receiver: Got SYN, sending SYN+ACK")
    syn_ack = Packet(0, FLAG_SYN | FLAG_ACK, syn.seq + 1, "")
    receiver_socket.sendto(syn_ack.pack(), addr)

    # wait for final ACK
    try:
        data, addr = receiver_socket.recvfrom(2048)
        final_ack = Packet.unpack(data)
        if (final_ack.flags & FLAG_ACK):
            print("Receiver: Handshake complete\n")
            return True, addr
    except timeout:
        print("Receiver: Timeout waiting for final ACK.")

    return False, None


def receive_data(addr):
    print("Receiver: Ready to receive data...")

    expected_seq = 0
    last_ack = 0

    buffer_size = 1024
    buffer_used = 0

    while True:
        try:
            data, sender = receiver_socket.recvfrom(4096)
        except timeout:
            print("Receiver: No data for a long time. Closing.")
            break

        pkt = Packet.unpack(data)

        # simulate dropping data packet
        if random.random() < 0.1:
            print("Receiver: Simulated data loss")
            continue

        print(f"Receiver: Got packet seq={pkt.seq}")

        payload_len = len(pkt.payload)

        # flow control check
        if buffer_used + payload_len > buffer_size:
            print("Receiver: Buffer full, advertising rwnd=0")
            ack = Packet(0, FLAG_ACK, last_ack, "", rwnd=0)
            receiver_socket.sendto(ack.pack(), addr)
            continue

        # correct in-order packet
        if pkt.seq == expected_seq:
            delivered = pkt.payload # Delivery to application layer
            print(f"Receiver: Delivered: {delivered}")

            buffer_used += payload_len
            expected_seq += payload_len
            last_ack = expected_seq

            rwnd = buffer_size - buffer_used
            ack = Packet(0, FLAG_ACK, last_ack, "", rwnd)
            receiver_socket.sendto(ack.pack(), addr)
            print(f"Receiver: Sent ACK {ack.ack} rwnd={rwnd}")

        else:
            # out-of-order
            print("Receiver: Out-of-order, resending last ACK")
            rwnd = buffer_size - buffer_used
            ack = Packet(0, FLAG_ACK, last_ack, "", rwnd)
            receiver_socket.sendto(ack.pack(), addr)


if __name__ == "__main__":
    ok, client = do_handshake()
    if ok:
        receive_data(client)
