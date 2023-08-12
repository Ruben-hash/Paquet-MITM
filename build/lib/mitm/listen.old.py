#!/usr/bin/python3

from scapy.all import sniff, IP
from scapy.layers.http import HTTPRequest
import sys
import time
from datetime import datetime
import json

if len(sys.argv) != 3:
    print("Erreur d'utilisation du script")
    exit()

nb_sec = int(sys.argv[1])
ip_client = sys.argv[2]

content = []

# Charger les données existantes depuis le fichier JSON
try:
    with open("capture.json", "r", encoding="utf-8") as filecontent:
        existing_data = json.load(filecontent)
    if isinstance(existing_data, list):
        content = existing_data
except FileNotFoundError:
    pass

def check(p):
    if HTTPRequest in p and p[IP].src == ip_client:
        req = p[HTTPRequest]

        request_data = {
            "Methode": req.Method.decode("utf-8"),
            "URI": req.Path.decode("utf-8"),
            "Version": req.Http_Version.decode("utf-8"),
            "IP client": p[IP].src,
            "IP serveur": p[IP].dst,
            "Date": str(datetime.now())
        }

        if req.Method.decode("utf-8") == "POST":
            request_data["contenu"] = req.payload.load.decode("utf-8")

        if request_data not in content:
            content.append(request_data)

    with open("capture.json", "w", encoding="utf-8") as filecontent:
        json.dump(content, filecontent, indent=4)

sniff(prn=check, timeout=nb_sec)
