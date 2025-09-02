import socket
import time
import tkinter as tk

SERVER_IP = "127.0.0.1"
SERVER_PORT = 9999
MESSAGE = b"Flood!"
DELAY = 0.000 

def send_packets(count):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"[Client] Sending {count} UDP packets to {SERVER_IP}:{SERVER_PORT} ...")
    start_time = time.time()

    for i in range(count):
        sock.sendto(MESSAGE, (SERVER_IP, SERVER_PORT))
        if DELAY > 0:
            time.sleep(DELAY)

    sock.close()
    elapsed = time.time() - start_time
    print(f"[Client] Done! Sent {count} packets in {elapsed:.2f}s ({count/elapsed:.2f} pkt/s)")

root = tk.Tk()
root.title("UDP Packet Sender")

label = tk.Label(root, text="Number of Packets to Send")
label.pack(pady=10)

slider = tk.Scale(root, from_=1, to=500, orient="horizontal", length=400)
slider.set(100)  
slider.pack(pady=10)

button = tk.Button(root, text="Send", command=lambda: send_packets(slider.get()))
button.pack(pady=10)

root.mainloop()


