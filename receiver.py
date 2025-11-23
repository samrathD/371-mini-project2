from socket import *
import struct
import random
import time

def compute_checksum(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b'\x00'  # pad odd length

    s = 0
    for i in range(0, len(data), 2):
        word = data[i] << 8 | data[i+1]
        s += word
        s = (s & 0xFFFF) + (s >> 16)

    return (~s) & 0xFFFF

# Packet structure
class Packet:
    def __init__(self, seq, flags, ack, payload, rwnd=0, checksum = 0):
        self.seq = seq
        self.flags = flags
        self.ack = ack
        self.payload = payload
        self.rwnd = rwnd
        self.checksum = checksum

    def pack(self):
        header = struct.pack("IIIBH", self.seq, self.ack, self.rwnd, self.flags, 0)
        pb = self.payload.encode()
        length = len(pb)

        length_part = struct.pack("I", length)
        raw = header + length_part + pb

        # Compute checksum over entire packet
        self.checksum = compute_checksum(raw) 

        # Rebuild header with checksum inserted
        header = struct.pack("IIIBH", self.seq, self.ack, self.rwnd,
                             self.flags, self.checksum)
        
        return header + length_part + pb

    @staticmethod
    def unpack(b):
        header_fmt = "IIIBH"
        HEADER_SIZE = struct.calcsize(header_fmt)   # = 16

        seq, ack, rwnd, flags, checksum = struct.unpack(header_fmt, b[:HEADER_SIZE])

        # Read payload length (next 4 bytes)
        length = struct.unpack("I", b[HEADER_SIZE:HEADER_SIZE+4])[0]

        payload_start = HEADER_SIZE + 4
        payload_end = payload_start + length
        payload = b[payload_start:payload_end].decode()

        # Build packet object
        pkt = Packet(seq, flags, ack, payload, rwnd, checksum)

        # Compute checksum on header with zeroed checksum + length + payload
        header_wo_checksum = struct.pack(header_fmt, seq, ack, rwnd, flags, 0)
        raw = header_wo_checksum + struct.pack("I", length) + b[payload_start:payload_end]

        calc = compute_checksum(raw)
        pkt.valid = (calc == checksum)

        return pkt


FLAG_SYN = 0b001
FLAG_ACK = 0b010
FLAG_FIN = 0b100

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

    # Drop invalid checksums
    if not syn.valid:
        print("Receiver: Dropped SYN due to bad checksum")
        return False, None

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
        if final_ack.valid and (final_ack.flags & FLAG_ACK):
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

    last_drain_time = time.time()
    drain_rate = 50 # bytes per second

    while True:
        try:
            data, sender = receiver_socket.recvfrom(4096)
        except timeout:
            print("Receiver: No data for a long time. Closing.")
            break

        pkt = Packet.unpack(data)

        # Consume datat with a rate, to free buffer
        current_time = time.time()
        elapsed = current_time - last_drain_time

        if elapsed >= 1.0:
            drained = int(drain_rate * elapsed)
            buffer_used = max(0, buffer_used - drained)
            last_drain_time = current_time

        # Invalid checksum
        if not pkt.valid:
            print(f"Receiver: Dropped corrupted packet seq={pkt.seq}")
            continue

        # simulate dropping data packet
        if random.random() < 0.4:
            print("\n***Receiver: Simulated data loss***\n")
            continue

        print(f"Receiver: Got packet seq={pkt.seq}")

        payload_len = len(pkt.payload)

        if pkt.flags & FLAG_FIN:
            print(f"Receiver: FIN Received, sending FIN_ACK")
            findAckPkt = Packet(0, flags=FLAG_FIN | FLAG_ACK, ack=0,payload="")
            receiver_socket.sendto(findAckPkt.pack(), addr)
            print("Sent FIN closing connection")
            break

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

            # buffer_used -= payload_len   # free space
            # buffer_used = max(buffer_used, 0)

            buffer_used += payload_len
            # expected_seq += payload_len
            expected_seq +=1
            # last_ack = expected_seq
            last_ack = expected_seq - 1

            rwnd = buffer_size - buffer_used
            ack = Packet(0, FLAG_ACK, last_ack, "", rwnd)
            receiver_socket.sendto(ack.pack(), addr)
            print(f"Receiver: Sent ACK {ack.ack} rwnd={rwnd}")
            time.sleep(0.5)

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
        receiver_socket.close()
