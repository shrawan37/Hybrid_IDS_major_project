# src/features.py
import time
from collections import defaultdict, deque
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6

# --- State Management ---
_WINDOW_SIZE = 100  # Features based on last 100 connections to same host
_TIME_WINDOW = 2.0  # Features based on last 2 seconds

# History for 2-second time window
# key: (dst_ip) or (dst_ip, service)
_TIME_HISTORY = defaultdict(deque) 
_TIME_REJ_HISTORY = defaultdict(deque)

# History for 100-connection host window
# key: dst_ip
_HOST_HISTORY = defaultdict(lambda: deque(maxlen=_WINDOW_SIZE))

def _prune_time_deque(dq, now):
    while dq and (now - dq[0]) > _TIME_WINDOW:
        dq.popleft()

# --- Common Mappings ---
_COMMON_SERVICES = {
    20: "ftp_data", 21: "ftp", 22: "ssh", 23: "telnet",
    25: "smtp", 53: "dns", 80: "http", 110: "pop_3", 
    143: "imap4", 443: "https", 3306: "mysql", 3389: "remote_desktop"
}

def infer_service(pkt):
    if TCP in pkt: return _COMMON_SERVICES.get(pkt[TCP].dport, "other")
    if UDP in pkt: return _COMMON_SERVICES.get(pkt[UDP].dport, "other")
    if ICMP in pkt: return "icmp"
    return "other"

def infer_flag(pkt):
    if TCP not in pkt: return "OTH"
    f = pkt[TCP].flags
    if f & 0x04: return "REJ" # RST
    if f & 0x02: return "S0"  # SYN only
    if f & 0x10: return "SF"  # ACK (Normal)
    return "OTH"

# --- Main Feature Extraction for Inference ---
def extract_features(pkt):
    now = time.time()
    
    # 1. Basic Identity
    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
    elif IPv6 in pkt:
        src_ip = pkt[IPv6].src
        dst_ip = pkt[IPv6].dst
    else:
        src_ip = "0.0.0.0"
        dst_ip = "0.0.0.0"

    src_port = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
    dst_port = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)
    
    protocol = "tcp" if TCP in pkt else ("udp" if UDP in pkt else ("icmp" if ICMP in pkt else "other"))
    service = infer_service(pkt)
    flag = infer_flag(pkt)
    
    # 2. Sizes
    src_bytes = float(len(pkt[TCP].payload)) if TCP in pkt else (float(len(pkt[UDP].payload)) if UDP in pkt else 0.0)
    dst_bytes = 0.0 # Single packet capture usually has 0 dst_bytes
    
    # 3. 2-Second Time Window Stats
    _prune_time_deque(_TIME_HISTORY[dst_ip], now)
    _TIME_HISTORY[dst_ip].append(now)
    count = float(len(_TIME_HISTORY[dst_ip]))
    
    _prune_time_deque(_TIME_HISTORY[(dst_ip, service)], now)
    _TIME_HISTORY[(dst_ip, service)].append(now)
    srv_count = float(len(_TIME_HISTORY[(dst_ip, service)]))
    
    # Error Rates (REJ)
    if flag == "REJ":
        _TIME_REJ_HISTORY[dst_ip].append(now)
        _TIME_REJ_HISTORY[(dst_ip, service)].append(now)
    
    _prune_time_deque(_TIME_REJ_HISTORY[dst_ip], now)
    _prune_time_deque(_TIME_REJ_HISTORY[(dst_ip, service)], now)
    
    rerror_rate = float(len(_TIME_REJ_HISTORY[dst_ip]) / count) if count > 0 else 0.0
    srv_rerror_rate = float(len(_TIME_REJ_HISTORY[(dst_ip, service)]) / srv_count) if srv_count > 0 else 0.0

    # 4. 100-Connection Host Window Stats
    history = _HOST_HISTORY[dst_ip]
    history.append((service, src_port, flag == "REJ", flag == "SF")) # Added flag_SF tracking
    
    dst_host_count = float(len(history))
    dst_host_srv_count = float(sum(1 for h in history if h[0] == service))
    dst_host_same_srv_rate = dst_host_srv_count / dst_host_count
    
    dst_host_same_src_port_rate = float(sum(1 for h in history if h[1] == src_port) / dst_host_count)
    dst_host_rerror_rate = float(sum(1 for h in history if h[2]) / dst_host_count)
    dst_host_srv_rerror_rate = float(sum(1 for h in history if h[0] == service and h[2]) / dst_host_srv_count) if dst_host_srv_count > 0 else 0.0

    # Calculate duration (simple approximation for frontend)
    try:
         timestamps = _TIME_HISTORY[dst_ip]
         if len(timestamps) > 1:
             duration = timestamps[-1] - timestamps[0]
         else:
             duration = 0.0
    except:
         duration = 0.0

    # 5. Return RAW features for the notebook inference logic
    return {
        # Numeric Features (24 expected by notebook scaler)
        "duration": float(duration),
        "src_bytes": float(src_bytes),
        "dst_bytes": float(dst_bytes),
        "land": 1.0 if src_ip == dst_ip else 0.0,
        "wrong_fragment": 0.0, # Hard to detect without more IP reassembly
        "urgent": 0.0,
        "hot": 0.0,
        "num_failed_logins": 0.0,
        "logged_in": 1.0 if flag == "SF" else 0.0,
        "num_compromised": 0.0,
        "root_shell": 0.0,
        "su_attempted": 0.0,
        "num_root": 0.0,
        "num_file_creations": 0.0,
        "num_shells": 0.0,
        "num_access_files": 0.0,
        "num_outbound_cmds": 0.0,
        "is_host_login": 0.0,
        "is_guest_login": 0.0,
        "count": count,
        "srv_count": srv_count,
        "rerror_rate": rerror_rate,
        "srv_rerror_rate": srv_rerror_rate,
        "dst_host_count": dst_host_count,
        "dst_host_srv_count": dst_host_srv_count,
        "dst_host_same_srv_rate": dst_host_same_srv_rate,
        "dst_host_same_src_port_rate": dst_host_same_src_port_rate,
        "dst_host_rerror_rate": dst_host_rerror_rate,
        "dst_host_srv_rerror_rate": dst_host_srv_rerror_rate,
        "level": 0.0,
        
        # Categorical Features
        "protocol_type": protocol,
        "service": service,
        "flag": flag,
        
        # Metadata for UI
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "length": len(pkt)
    }

# --- Wrapper class for compatibility ---
class FeatureExtractor:
    def __init__(self):
        pass

    def extract_packet_features(self, pkt):
        return extract_features(pkt)