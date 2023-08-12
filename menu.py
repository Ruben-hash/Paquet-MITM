#!/usr/bin/python3

from mitm.atk import atk
from mitm.atk import dhcp
from mitm.listen import HTTP
from mitm.listen import dns
from mitm.detection import arp

def afficher_menu():
    """Affichage du menu"""
    phrase2 = "\n Menu \n"
    phrase_option = " [M] Menu Principal \n [ARP] ARP Poissonning "
    phrase3 = "\n [DA] ARP Detection  \n [DHCP] DHCP SPOOFING"
    phrase_option2 = " [DNS] Ecoute DNS \n [HTTP] Ecoute HTTP"
    phrase_fin = "\n [Q] Quitter le programme"
    print("*" * 40 + phrase2 + phrase_option + phrase3)
    print(phrase_option2 + phrase_fin + "\n" + "*" * 40)

def main():
    """
    Fonction principale du programme:
    Elle appelle les commandes correspondantes à la saisie utilisateur
    """
    rep = input(" >Entrez votre commande (M pour afficher le menu ) : ").upper()
    if rep == "M":
        afficher_menu()
        main()
    elif rep == "ARP":
        print("--- Début de l'empoissonnement des tables ---")
        atk(input("Adresse ip du client : "), input("Adresse ip du serveur : "))
        main()
    elif rep == "DA":
        print("--- Détection ---")
        arp()
        main()
    elif rep == "HTTP":
        print("--- Début du processus ---")
        HTTP(input("IP de la victime : "), int(input("Temps : ")))
        main()
    elif rep == "DNS":
        print("--- Début du processus ---")
        dns(input("IP de la victime : "), int(input("Temps : ")))
        main()
    elif rep == "DHCP":
        print("--- Début du processus ---")
        dhcp(input("IP à définir en route : "), input("IP de la victime : "))
        main()
    elif rep == "Q":
        print("---Fin---")

main()
