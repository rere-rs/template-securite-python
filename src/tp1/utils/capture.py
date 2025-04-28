from src.tp1.utils.lib import choose_interface
from src.tp1.utils.config import logger
from scapy.all import sniff, Packet, TCP, UDP, ICMP, ARP, Raw, IP
from typing import List, Dict


class Capture:
    def __init__(self) -> None:
        self.interface = choose_interface()
        self.summary = ""
        self.packets: List[Packet] = []
        self.protocol_counts: Dict[str, int] = {}
        self.attacks_detected: List[str] = []

    def capture_trafic(self) -> None:
        """
        Capture network traffic from the selected interface
        """
        logger.info(f"Starting capture on interface: {self.interface}")
        self.packets = sniff(iface=self.interface, timeout=30)
        logger.info(f"Capture complete. {len(self.packets)} packets captured.")

    def sort_network_protocols(self) -> None:
        """
        Analyze captured packets and count occurrences of each protocol.
        """
        self.protocol_counts = {}
        for pkt in self.packets:
            if pkt.haslayer(TCP):
                proto = "TCP"
            elif pkt.haslayer(UDP):
                proto = "UDP"
            elif pkt.haslayer(ICMP):
                proto = "ICMP"
            elif pkt.haslayer(ARP):
                proto = "ARP"
            else:
                proto = "Other"
            self.protocol_counts[proto] = self.protocol_counts.get(proto, 0) + 1
        logger.info(f"Protocol counts: {self.protocol_counts}")

    def get_all_protocols(self) -> Dict[str, int]:
        """
        Return all protocols captured with total packets number
        """
        if not self.protocol_counts:
            self.sort_network_protocols()
        return self.protocol_counts

    def detect_arp_spoofing(self) -> None:
        """
        Detect ARP spoofing: multiple MACs claiming the same IP address
        """
        ip_mac_mapping = {}
        for pkt in self.packets:
            if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # is-at (reply)
                ip = pkt[ARP].psrc
                mac = pkt[ARP].hwsrc
                if ip in ip_mac_mapping and ip_mac_mapping[ip] != mac:
                    attack_msg = f"ARP Spoofing detected: IP {ip} with multiple MACs ({ip_mac_mapping[ip]} vs {mac})"
                    logger.warning(attack_msg)
                    self.attacks_detected.append(attack_msg)
                else:
                    ip_mac_mapping[ip] = mac

    def detect_sql_injection(self) -> None:
        """
        Detect potential SQL Injection patterns in TCP payloads
        """
        suspicious_patterns = ["' OR '1'='1", "UNION SELECT", "DROP TABLE", "admin'--", "OR 1=1"]
        for pkt in self.packets:
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                payload = pkt[Raw].load.decode(errors="ignore").lower()
                for pattern in suspicious_patterns:
                    if pattern.lower() in payload:
                        src_ip = pkt[IP].src if pkt.haslayer(IP) else "Unknown IP"
                        attack_msg = f"SQL Injection attempt detected from {src_ip}"
                        logger.warning(attack_msg)
                        self.attacks_detected.append(attack_msg)
                        break

    def analyse(self, protocols: str) -> None:
        """
        Analyse all captured data and return statement
        Si un tra c est illégitime (exemple : Injection SQL, ARP
        Spoo ng, etc)
        a Noter la tentative d'attaque.
        b Relever le protocole ainsi que l'adresse réseau/physique
        de l'attaquant.
        c (FACULTATIF) Opérer le blocage de la machine
        attaquante.
        Sinon a cher que tout va bien
        """
        self.get_all_protocols()
        self.sort_network_protocols()

        logger.info("Starting legitimacy analysis...")
        self.detect_arp_spoofing()
        self.detect_sql_injection()

        if not self.attacks_detected:
            logger.info("No suspicious traffic detected.")

        self.summary = self.gen_summary()

    def get_summary(self) -> str:
        """
        Return the analysis summary.
        """
        return self.summary

    def gen_summary(self) -> str:
        """
        Generate summary report for findings
        """
        if self.attacks_detected:
            summary = "ATTACKS DETECTED:\n"
            for attack in self.attacks_detected:
                summary += f"- {attack}\n"
        else:
            summary = "No suspicious activity detected during capture.\n"
        return summary