#!/usr/bin/env python3

from scapy.all import sniff, ARP

def arp():
# Dictionnaire pour stocker les adresses MAC associées à chaque adresse IP
    mac_addresses = {}

    def process_packet(packet):
        # Opération ARP Request ou ARP Reply
        if ARP in packet and packet[ARP].op in (1, 2):
		
            if packet[ARP].hwsrc != packet[ARP].hwdst:
                print("Alerte ! Attaque d'empoisonnement ARP détectée :")
                print("IP source usurpe: {}".format(packet[ARP].psrc))
                print("Adresse MAC attaquant : {}".format(packet[ARP].hwsrc))
                print("-----------------------------")

# Sniffer le trafic ARP en utilisant la fonction process_packet comme rappel
    sniff(filter="arp", prn=process_packet)
arp()
