import pyshark
import socket
import time
import matplotlib.pyplot as plt
import matplotlib.animation as animation
from threading import Thread
from collections import deque

INTERFACE = "\\Device\\NPF_Loopback"  
CLIENT_IP = "127.0.0.1"
PORT = 9999
DDOS_THRESHOLD = 50
ACK_MESSAGE = b"ACK"
PACKET_LIMIT = 20000

packet_log = []
udp_sent_count = 0
start_time = time.time()
packet_rates = deque(maxlen=20)  

def analyze_traffic():
    global packet_log
    while True:
        time.sleep(5)
        now = time.time()
        packet_log = [t for t in packet_log if now - t < 5]  
        packet_rate = len(packet_log) / 5
        packet_rates.append(packet_rate)

        print(f"\n[Analysis] {len(packet_log)} packets in last 5s (Rate: {packet_rate:.2f} pkt/s)")
        if len(packet_log) > DDOS_THRESHOLD:
            print("[ALERT] Potential DDoS detected!")
        else:
            print("[OK] Traffic normal.")

def respond_to_sender(ip, port):
    """Send ACK back to sender."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(ACK_MESSAGE, (ip, port))
        sock.close()
        print(f"[ACK] Sent ACK to {ip}:{port}")
    except Exception as e:
        print(f"[Error] Failed to send ACK: {e}")

def live_plot():
    fig, ax = plt.subplots()
    ax.set_ylim(0, 100) 
    ax.set_title("UDP Packet Rate (packets/sec)")
    ax.set_xlabel("Time (5s windows)")
    ax.set_ylabel("Rate")

    line, = ax.plot([], [], lw=2)

    def update(frame):
        ax.set_xlim(0, max(10, len(packet_rates)))  
        line.set_data(range(len(packet_rates)), list(packet_rates))
        return line,

    ani = animation.FuncAnimation(fig, update, interval=1000)
    plt.show()

def start_packet_sniffer():
    global udp_sent_count
    print(f"[PyShark] Capturing UDP from {CLIENT_IP} to port {PORT} on '{INTERFACE}'")
    capture = pyshark.LiveCapture(
        interface=INTERFACE,
        display_filter=f"udp and ip.src == {CLIENT_IP} and udp.dstport == {PORT}"
    )

    for i, packet in enumerate(capture.sniff_continuously(packet_count=PACKET_LIMIT)):
        try:
            udp_sent_count += 1
            ip_src = packet.ip.src
            ip_dst = packet.ip.dst
            udp_srcport = int(packet.udp.srcport)

            packet_log.append(time.time())
            print(f"[Capture #{udp_sent_count}] {ip_src}:{udp_srcport} -> {ip_dst}:{PORT}")

            Thread(target=respond_to_sender, args=(ip_src, udp_srcport), daemon=True).start()

        except AttributeError:
            continue

    elapsed_time = time.time() - start_time
    print("\n=== SUMMARY ===")
    print(f"Total UDP packets from {CLIENT_IP}: {udp_sent_count}")
    print(f"Time elapsed: {elapsed_time:.2f} sec")
    if elapsed_time > 0:
        print(f"Average rate: {udp_sent_count / elapsed_time:.2f} pkt/s")

if __name__ == "__main__":
    Thread(target=analyze_traffic, daemon=True).start()
    Thread(target=live_plot, daemon=True).start()
    start_packet_sniffer()

