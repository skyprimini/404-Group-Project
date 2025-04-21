import logging
import json
from datetime import datetime

class AlertSystem:
    def __init__(self, log_file="ids_alerts.log", enable_console=True):
        self.logger = logging.getLogger("IDS_Alerts")
        self.logger.setLevel(logging.INFO)

        # Avoid duplicate handlers if the logger is reloaded
        if not self.logger.handlers:
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s'
            ))
            self.logger.addHandler(file_handler)

            #Also log to console
            if enable_console:
                console_handler = logging.StreamHandler()
                console_handler.setFormatter(logging.Formatter(
                    '%(asctime)s - %(levelname)s - %(message)s'
                ))
                self.logger.addHandler(console_handler)

    def generate_alert(self, threat, packet_info, notify_callback=None):
        confidence = threat.get('confidence', 0.0)

        alert = {
            'timestamp': datetime.now().isoformat(),
            'summary': f"{threat['type'].capitalize()} threat detected",
            'threat_type': threat['type'],
            'source_ip': packet_info.get('source_ip'),
            'destination_ip': packet_info.get('destination_ip'),
            'confidence': confidence,
            'details': threat
        }

        # Determine log level based on severity
        if confidence > 0.8:
            self.logger.critical(json.dumps(alert))
        elif confidence > 0.5:
            self.logger.warning(json.dumps(alert))
        else:
            self.logger.info(json.dumps(alert))

        # notify via external hook
        if notify_callback:
            notify_callback(alert)
