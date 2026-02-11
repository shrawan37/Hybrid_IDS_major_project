# src/features.py
import time
from collections import defaultdict, deque
from scapy.layers.inet import IP, TCP, UDP, ICMP
<<<<<<< HEAD

# --- Flow counters (stateful, pruned by time window) ---
_FLOW_WINDOW_SEC = 2.0
_SRC_COUNTS = defaultdict(deque)        # src_ip -> deque[timestamps]
_SRV_COUNTS = defaultdict(deque)        # (dst_ip, dst_port) -> deque[timestamps]

def _prune_deque(dq, now, window=_FLOW_WINDOW_SEC):
    while dq and (now - dq[0]) > window:
        dq.popleft()

def _track_src_count(src_ip, now):
    dq = _SRC_COUNTS[src_ip]
    dq.append(now)
    _prune_deque(dq, now)
    return len(dq)

def _track_srv_count(dst_ip, dst_port, now):
    key = (dst_ip, dst_port)
    dq = _SRV_COUNTS[key]
    dq.append(now)
    _prune_deque(dq, now)
    return len(dq)

# --- Service inference from ports ---
_COMMON_SERVICES = {
    20: "ftp_data", 21: "ftp", 22: "ssh", 23: "telnet",
    25: "smtp", 53: "dns", 67: "dhcp", 68: "dhcp",
    80: "http", 110: "pop_3", 123: "ntp_u", 143: "imap4",
    443: "https", 465: "smtps", 993: "imaps", 995: "pop3s",
    6667: "IRC", 6000: "X11",
}

def infer_service(pkt):
    if TCP in pkt:
        dport = int(pkt[TCP].dport)
        return _COMMON_SERVICES.get(dport, "other")
    if UDP in pkt:
        dport = int(pkt[UDP].dport)
        if dport == 53:
            return "dns"
        if dport == 123:
            return "ntp_u"
        return _COMMON_SERVICES.get(dport, "other")
    if ICMP in pkt:
        return "icmp"
    return "other"

# --- TCP flag categorization ---
def infer_flag(pkt):
    if TCP not in pkt:
        return "OTH"
    flags = pkt[TCP].flags
    syn = bool(flags & 0x02)
    ack = bool(flags & 0x10)
    fin = bool(flags & 0x01)
    rst = bool(flags & 0x04)
    if syn and not ack and not fin and not rst:
        return "S0"
    if syn and ack and not rst:
        return "SF"
    if ack and not syn and not rst:
        return "SF"
    if rst and ack:
        return "REJ"
    if rst and not ack:
        return "RSTO"
    if syn and rst:
        return "SH"
    if fin and ack:
        return "SF"
    return "OTH"

# --- Utility: payload sizes ---
def payload_size(pkt):
    try:
        return int(len(bytes(pkt.payload)))
    except Exception:
        return 0

def l4_payload_size(pkt):
    if TCP in pkt:
        try:
            return int(len(bytes(pkt[TCP].payload)))
        except Exception:
            return 0
    if UDP in pkt:
        try:
            return int(len(bytes(pkt[UDP].payload)))
        except Exception:
            return 0
    return 0

# --- Main feature extraction ---
def extract_features(pkt):
    now = time.time()
    src_ip = pkt[IP].src if IP in pkt else "0.0.0.0"
    dst_ip = pkt[IP].dst if IP in pkt else "0.0.0.0"
    ttl = int(pkt[IP].ttl) if IP in pkt else 0

    if TCP in pkt:
        protocol_type = "tcp"
        dst_port = int(pkt[TCP].dport)
        src_bytes = len(bytes(pkt[TCP].payload))
    elif UDP in pkt:
        protocol_type = "udp"
        dst_port = int(pkt[UDP].dport)
        src_bytes = len(bytes(pkt[UDP].payload))
    elif ICMP in pkt:
        protocol_type = "icmp"
        dst_port = 0
        src_bytes = len(bytes(pkt[ICMP].payload))
    else:
        protocol_type = "other"
        dst_port = 0
        src_bytes = 0

    service = infer_service(pkt)
    flag = infer_flag(pkt)
    count = _track_src_count(src_ip, now)
    srv_count = _track_srv_count(dst_ip, dst_port, now)

    fragmented = False
    if IP in pkt:
        try:
            fragmented = bool(pkt[IP].flags & 0x1) or (pkt[IP].frag > 0)
        except Exception:
            fragmented = False

    src_bytes_val = l4_payload_size(pkt)
    dst_bytes_val = 0
    total_payload = payload_size(pkt)

    icmp_type = pkt[ICMP].type if ICMP in pkt else None
    icmp_code = pkt[ICMP].code if ICMP in pkt else None

    # Calculate duration
    flow_key = (src_ip, dst_ip, dst_port, protocol_type)
    if flow_key not in _SRC_COUNTS: # Abuse _SRC_COUNTS slightly or just use new dict
         # Simple duration based on time check (stateless approximation or need new state)
         # For now, let's use a simple randomize or kept 0.0 if state is too complex for this snippet
         # But the plan asked to fix it.
         pass
         
    # Better approach: Use the existing _track_src_count timestamps to estimate activity duration
    try:
         timestamps = _SRC_COUNTS[src_ip]
=======
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
>>>>>>> main
         if len(timestamps) > 1:
             duration = timestamps[-1] - timestamps[0]
         else:
             duration = 0.0
    except:
         duration = 0.0

<<<<<<< HEAD
    return {
        "duration": float(duration),
        "src_bytes": float(src_bytes_val),
        "dst_bytes": float(dst_bytes_val),
        "count": float(count),
        "srv_count": float(srv_count),
        "protocol_type": protocol_type,
        "service": service,
        "flag": flag,
        "ttl": ttl,
        "fragmented": fragmented,
        "payload_size": total_payload,
        "icmp_type": icmp_type,
        "icmp_code": icmp_code,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
=======
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
>>>>>>> main
    }

# --- Wrapper class for compatibility ---
class FeatureExtractor:
    def __init__(self):
        pass

    def extract_packet_features(self, pkt):
        return extract_features(pkt)