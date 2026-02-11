class HybridEngine:
    def __init__(self, signature_engine, anomaly_engine, threshold=0.6, weight_sig=0.4, weight_anom=0.6):
        self.sig = signature_engine
        self.anom = anomaly_engine
        self.threshold = threshold
        self.w_sig = weight_sig
        self.w_anom = weight_anom

    def analyze(self, pkt, feat):
        """
        Returns dict: {'malicious': bool, 'reasons':[], 'score': float}
        """
        # 1. Signature-based detection (First Line of Defense)
        # As per workflow: If signature matches, classify as threat immediately.
        sig_mal, sig_reason, sig_score = self.sig.check_packet(pkt)

        if sig_mal:
            return {
                'malicious': True,
                'reasons': [sig_reason or "Used Known Signature"],
                'score': 1.0  # Max certainty
            }

        # 2. Anomaly-based detection (Second Line of Defense)
<<<<<<< HEAD
=======
        # Skip anomaly detection for whitelisted IPs or IPv6 to reduce noise and CPU load
        # (Current model is optimized for IPv4 NSL-KDD patterns)
        src_ip = feat.get("src_ip", "")
        if ":" in src_ip or self.sig.is_whitelisted(src_ip):
            return {'malicious': False, 'reasons': [], 'score': 0.0}
            
>>>>>>> main
        # Only run if signature check failed (optimization)
        anom_result = self.anom.analyze(feat)
        anom_mal = anom_result.get("malicious", False)
        anom_score = anom_result.get("score", 0.0)

        # Combine scores (dominated by anomaly score since signature was roughly 0)
        # Using a safer combination logic
        combined_score = anom_score 
        malicious = anom_mal

        reasons = []
        if anom_mal:
<<<<<<< HEAD
            reasons.append("Anomaly Detected")
=======
            reasons.append("Suspicious Behaviour")
>>>>>>> main

        return {
            'malicious': malicious,
            'reasons': reasons,
            'score': combined_score
        }