from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from datetime import datetime
import os

class ReportGenerator:
    def __init__(self, report_dir="reports"):
        self.report_dir = report_dir
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir)

    def generate_report(self, packet_stats, threat_log):
        """
        Generate a PDF report summarising the session.
        packet_stats: dict {'TCP': 10, 'UDP': 5...}
        threat_log: list of dicts [{'time':..., 'threat':...}]
        """
        try:
            filename = f"IDS_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            filepath = os.path.join(self.report_dir, filename)
            
            c = canvas.Canvas(filepath, pagesize=letter)
            width, height = letter
            
            # Title
            c.setFont("Helvetica-Bold", 20)
            c.drawString(50, height - 50, "Intrusion Detection System Report")
            
            c.setFont("Helvetica", 12)
            c.drawString(50, height - 80, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            
            # Statistics Section
            c.setFont("Helvetica-Bold", 14)
            c.drawString(50, height - 120, "Traffic Statistics")
            
            y = height - 150
            c.setFont("Helvetica", 12)
            for proto, count in packet_stats.items():
                c.drawString(70, y, f"{proto}: {count} packets")
                y -= 20
                
            # Threats Section
            y -= 20
            c.setFont("Helvetica-Bold", 14)
            c.drawString(50, y, "Detected Threats")
            y -= 30
            
            c.setFont("Helvetica", 10)
            if not threat_log:
                c.drawString(70, y, "No threats detected in this session.")
            else:
                for threat in threat_log:
                    if y < 50: # New page if full
                        c.showPage()
                        y = height - 50
                    
                    text = f"[{threat.get('time')}] {threat.get('threat')} (Src: {threat.get('src')})"
                    c.drawString(70, y, text)
                    y -= 15
            
            c.save()
            return True, filepath
        except Exception as e:
            return False, str(e)
