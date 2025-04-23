from src.tp1.utils.lib import choose_interface
from src.tp1.utils.config import logger
from scapy.all import sniff, Packet, TCP, UDP, ICMP, ARP
from typing import List, Dict

class Capture:
    def __init__(self) -> None:
        self.interface = choose_interface()
        self.summary = ""
        # List to store captured packets
        self.packets: List[Packet] = []
        self.protocol_counts: Dict[str, int] = {}  # Dictionary to store protocol counts

    def capture_trafic(self) -> None:
        """
        Capture network trafic from an interface
        """
        interface = self.interface
        logger.info(f"Starting capture on interface: {self.interface}")
        # Utilisation de sniff() pour capturer les paquets
        self.packets = sniff(iface=self.interface, timeout=5)
        logger.info(f"Capture complete. {len(self.packets)} packets captured.")

    def sort_network_protocols(self) -> None:
        """
        Sort and return all captured network protocols
        """
        self.protocol_counts = {}  # Reset protocol counts

        for pkt in self.packets:
            # Check each protocol in order of specificity
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

            # Increment the count for the detected protocol
            self.protocol_counts[proto] = self.protocol_counts.get(proto, 0) + 1

        # Log the results for debugging or confirmation
        logger.info(f"Protocol counts: {self.protocol_counts}")

    def get_all_protocols(self) -> Dict[str, int]:
        """
        Return all protocols captured with total packets number
        """
        if not self.protocol_counts:
            self.sort_network_protocols()
        return self.protocol_counts

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
        all_protocols = self.get_all_protocols()
        sort = self.sort_network_protocols()
        self.summary = self.gen_summary()

    def get_summary(self) -> str:
        return self.summary

    def gen_summary(self) -> str:
        """
        Generate summary
        """
        summary = ""
        return summary
