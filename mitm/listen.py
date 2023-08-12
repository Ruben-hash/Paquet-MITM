#!/usr/bin/python3

"""Paquet python utilisé """
from scapy.all import sniff, IP, DNSQR
from scapy.layers.http import HTTPRequest
import sys
from datetime import datetime
import json
import sqlite3

# Charger les données existantes depuis le fichier JSON
content = []
try:
    with open("capture.json", "r", encoding="utf-8") as filecontent:
        existing_data = json.load(filecontent)
    if isinstance(existing_data, list):
        content = existing_data
except FileNotFoundError:
    pass


def dns(ip, nb):
    """
    Fonction qui écoute le trafic réseau et 
    capture les paquets venant de l'ip mis en paramètre
    """
    #recuperation des paquet qui utilise le port 53
    packets = sniff(filter="host {} and port 53".format(ip), timeout=nb)
    dns_queries = [pkt[DNSQR].qname.decode() for pkt in packets if DNSQR in pkt]
    for query in dns_queries:
        print(query)





def HTTP(ip_client, nb_sec):
    """
    Fonction capturant les paquets HTTP du client
    """
    #Connection au fichier capture.db
    conn = sqlite3.connect('capture.db')
    cursor = conn.cursor()
    #Creation de la table SQL dans le fichier
    cursor.execute('''CREATE TABLE IF NOT EXISTS captures (
            date TEXT,
            IP TEXT,
            methode TEXT,
            URI TEXT
       )''')
    #Ecoute pendant un temps defini
    packets = sniff(timeout=nb_sec)
    for p in packets:
        #Filtre de recuperation des paquets HTTP du client
        if HTTPRequest in p and p[IP].src == ip_client:
            req = p[HTTPRequest]
            #creation d'un dictionnaire pour la recuperations des données
            request_data = {
                "Methode": req.Method.decode("utf-8"),
                "URI": req.Path.decode("utf-8"),
                "Version": req.Http_Version.decode("utf-8"),
                "IP serveur": p[IP].dst,
                "Date": str(datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"))
            }
            #Si la méthode Post est utilise, ajout du payload dans la variable
            if req.Method.decode("utf-8") == "POST":
                request_data["contenu"] = req.payload.load.decode("utf-8")
            #ajout des nouvelles donnees interceptee
            if request_data not in content:
                content.append(request_data)
            #insertion des donnees dans la base de donnees
            cursor.execute(
                'INSERT INTO captures (date,IP,methode,URI) VALUES(?, ?, ?, ?)',
                (
                    request_data['Date'],
                    request_data['IP serveur'],
                    request_data['Methode'],
                    request_data['URI']
                )
            )
            
            print(request_data['Date'], ";", request_data['IP serveur'], 
                ";", request_data['Methode'], ";", request_data['URI'])
            with open("capture.json", "w", encoding="utf-8") as filecontent1:
                json.dump(content, filecontent1, indent=4)
    #enregistrement des ajouts et fermeture du fichier
    conn.commit()
    conn.close()
