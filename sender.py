from socket import *
import struct
import time
import random

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
        HEADER_SIZE = struct.calcsize(header_fmt)  

        seq, ack, rwnd, flags, checksum = struct.unpack(header_fmt, b[:HEADER_SIZE])

        # Read payload length 
        length = struct.unpack("I", b[HEADER_SIZE:HEADER_SIZE+4])[0]

        payload_start = HEADER_SIZE + 4
        payload_end = payload_start + length
        payload = b[payload_start:payload_end].decode("latin1")

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

CHUNK_SIZE = 256
WINDOW_SIZE = 5

# IP will change based on device
reciverAddr = ("192.168.1.76",1200)
sender_socket = socket(AF_INET, SOCK_DGRAM)
sender_socket.bind(("", 1400))
sender_socket.settimeout(20)

#  Handshake function
def handshake():
    try:
        print("Sending SYN")
        syn =Packet(0,FLAG_SYN,0,"")
        sender_socket.sendto(syn.pack(),reciverAddr)
        print("Sent SYN, waiting for SYN-ACK")
    except OSError as err:
        print(f"Error sending SYN caught an OS error {err}")
    
    # Receive SYN-ACK from the reciever
    try:
        data, addr = sender_socket.recvfrom(2048)
        if addr!=reciverAddr:
            print(f"Incorrect packet from incorrect address {addr}")
            return False
        
        synAck = Packet.unpack(data)

        if not synAck.valid:
            print("Sender: Dropped corrupted SYN-ACK")
            return False

        if(synAck.flags&FLAG_SYN) and (synAck.flags&FLAG_ACK):
            print(f"Received SYN-ACK from {addr}, sending ACK")
            print("Sender handshake completed \n \n")
            # Send Final Ack
            ack = Packet(0, FLAG_ACK, synAck.seq+1,"")
            sender_socket.sendto(ack.pack(), reciverAddr)
            return True
        
    except timeout:
        print("Handshake timed out")

    return False

#  Main send loop
def send_file(filename):
    print(f"Sending file {filename}")

    MAX_INACTIVITY = 30   # seconds with no ACKs
    last_activity = time.time()

    # Initialize receiver window size
    rwnd_packets = WINDOW_SIZE

    # Congestion control
    cwnd = 1
    ssthresh = 8
    dup_ack_count = 0
    last_ack_seen = -1

    # Go back N variables
    base = 0
    nextSeq = 0
    timer_start = None
    TIMER_DURATION = 5

    chunks = []
    with open(filename,"rb") as f:
        while True:
            block = f.read(CHUNK_SIZE)
            if not block:
                break
            chunks.append(block)

    total = len(chunks)
    print(f"Total chunks: {total}")

    send_buffer = {}

    while base < total:
        # Determine the correct window size
        senderWindow = int(min(rwnd_packets, cwnd))

        # send packets in window
        while nextSeq < base + senderWindow and nextSeq < total:
            payload = chunks[nextSeq].decode("latin1")
            pkt = Packet(nextSeq, flags=0, ack=0, payload=payload)
            packed = pkt.pack()
            send_buffer[nextSeq] = packed

            # Corrupt packet to test for checksum 
            if random.random() < 0.1:
                print("\n***Sender: Corrupting packet***\n")
                # Make a mutable copy
                corrupted = bytearray(packed)

                # Flip a random bit in a random byte
                idx = random.randint(0, len(corrupted)-1)
                corrupted[idx] ^= 0xFF

                sender_socket.sendto(bytes(corrupted), reciverAddr)
                print(f"Sent CORRUPTED packet {nextSeq}")
                nextSeq += 1
                continue

            sender_socket.sendto(packed, reciverAddr)
            print(f"\nSent packet {nextSeq}")

            if base == nextSeq:
                timer_start = time.time()

            nextSeq += 1

        # Wait for ACK
        try:
            sender_socket.settimeout(1)
            data, addr = sender_socket.recvfrom(2048)
            last_activity = time.time()
            ackp = Packet.unpack(data)

            # Invalid checksum
            if not ackp.valid:
                print("Sender: Dropped corrupted ACK")
                continue

            acknum = ackp.ack
            rwnd_bytes = ackp.rwnd
            rwnd_packets = max(rwnd_bytes//CHUNK_SIZE,1)

            print(f"Received ACK: {acknum} and rwnd {rwnd_packets}")

            if acknum > last_ack_seen:
                last_ack_seen = acknum
                dup_ack_count = 0

                # Congestion control update
                if cwnd < ssthresh:
                    cwnd+=1
                # Congestion avoidance
                else:
                    cwnd+= 1/cwnd

                base = acknum + 1
                if base == nextSeq:
                    timer_start = None
                else:
                    timer_start = time.time()

            # Duplicate ACK
            else:
                if acknum == last_ack_seen:
                    dup_ack_count+=1
                    print(f"Duplicate ACK {acknum} ({dup_ack_count})")

                    # 3 duplicate ACKs
                    if dup_ack_count == 3:
                        ssthresh = max(int(cwnd//2),1)
                        oldCwnd = cwnd
                        cwnd = ssthresh
                        
                        print(f"\n Congestion window went from {oldCwnd} -> {cwnd}\n")

                        # Resend missing segment
                        missing =  acknum + 1 
                        if missing in send_buffer:
                            sender_socket.sendto(send_buffer[missing], reciverAddr)
                            print(f"Fast retransmit of packet {missing}")

                        timer_start = time.time()
                        
        except timeout:
            pass

        # Abort if no ACKs for too long
        if time.time() - last_activity > MAX_INACTIVITY:
            print("\n*** Sender aborting: receiver inactive too long ***\n")
            return
        
        # Check Timeout
        if timer_start and time.time() - timer_start > TIMER_DURATION:
            print("\n***Timeout occured resending window***\n")

            # Update congestion window
            ssthresh = max(int(cwnd//2),1)
            cwnd = 1
            dup_ack_count = 0
            print(f"Timeout CC: cwnd reset to {cwnd}, ssthresh={ssthresh}")

            # Retransmit window
            for seq in range(base, nextSeq):
                sender_socket.sendto(send_buffer[seq], reciverAddr)
                print(f"Resent packet {seq}")

            timer_start = time.time()
        



    print("File sent correctly.")   

    # Send FIN flag after sending all the data
    sender_socket.settimeout(1)
    fin_pkt = Packet(seq=nextSeq, flags=FLAG_FIN, ack=0,payload="")
    sender_socket.sendto(fin_pkt.pack(), reciverAddr)
    print("Sent FIN")

    # Wait for FIN-ACK
    while True:
        data, addr = sender_socket.recvfrom(2048)
        pkt = Packet.unpack(data)
        if (pkt.flags & FLAG_FIN) and (pkt.flags & FLAG_ACK):
            print("Received FIN-ACK closing connection")
            break

if __name__ == "__main__":
    filename = "test.txt"
    if handshake():
        send_file(filename)
        sender_socket.close()
