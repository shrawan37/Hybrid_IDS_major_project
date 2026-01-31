# src/ui.py
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import queue
import time
from scapy.all import Raw
from capture import PacketCapture
from features import FeatureExtractor
from signature import SignatureEngine
from anomaly import AnomalyEngine
from hybrid_engine import HybridEngine
from db import ThreatDB

MODEL_PATH = "../model/isof_model.joblib"  # adjust path

class IDSApp:
    def __init__(self, root):
        self.root = root
        root.title("Hybrid IDS - Tkinter + IsolationForest")

        # UI elements
        self.packet_tree = ttk.Treeview(root, columns=("time","src","dst","proto","len","score"), show="headings")
        for c in ("time","src","dst","proto","len","score"):
            self.packet_tree.heading(c, text=c)
        self.packet_tree.pack(fill="both", expand=True)

        self.log_text = tk.Text(root, height=8)
        self.log_text.pack(fill="x")

        # backend components
        self.q = queue.Queue()
        self.fe = FeatureExtractor()
        self.sig = SignatureEngine()
        self.anom = AnomalyEngine(MODEL_PATH)
        self.hybrid = HybridEngine(self.sig, self.anom)
        self.db = ThreatDB()

        self.packet_capture = PacketCapture(packet_callback=self.on_packet)
        self.packet_capture.start()

        # process loop
        self.root.after(200, self.process_queue)

    def on_packet(self, pkt):
        # Put packet into queue for GUI thread to process
        self.q.put(pkt)

    def process_queue(self):
        processed = 0
        while not self.q.empty() and processed < 50:
            pkt = self.q.get()
            feat = self.fe.extract_packet_features(pkt)
            res = self.hybrid.analyze(pkt, feat)
            now = time.strftime("%H:%M:%S")
            proto = feat.get('proto',0)
            pkt_len = feat.get('pkt_len',0)
            score = round(res['score'], 3)
            src = pkt[0][1].src if len(pkt.layers())>1 and pkt.haslayer('IP') else "?"
            dst = pkt[0][1].dst if len(pkt.layers())>1 and pkt.haslayer('IP') else "?"
            self.packet_tree.insert("", 0, values=(now, src, dst, proto, pkt_len, score))
            if res['malicious']:
                reason = ",".join(res['reasons'])
                self.log_text.insert("end", f"[{now}] ALERT {src} -> {dst} score={score} reason={reason}\n")
                self.db.insert_alert(src, dst, reason, score)
            processed += 1

        self.root.after(200, self.process_queue)

if __name__ == "__main__":
    root = tk.Tk()
    app = IDSApp(root)
    root.mainloop()
