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
        # Signature-based detection
        sig_mal, sig_reason, sig_score = self.sig.check_packet(pkt)

        # Anomaly-based detection
        anom_result = self.anom.analyze(feat)
        anom_mal = anom_result["malicious"]
        anom_score = anom_result["score"]

        # Combine scores
        combined_score = self.w_sig * sig_score + self.w_anom * anom_score
        malicious = sig_mal or (combined_score >= self.threshold)

        # Reasoning
        reasons = []
        if sig_mal:
            reasons.append(sig_reason or "signature")
        if anom_mal:
            reasons.append("anomaly")

        return {
            'malicious': malicious,
            'reasons': reasons,
            'score': combined_score
        }