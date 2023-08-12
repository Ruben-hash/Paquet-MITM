#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""Script d'installation du paquet mitm."""

from setuptools import setup
import mitm

setup(
	name="mitm",
	version=mitm.version,
	description="Paquet d'attaque ARP poisonning destiné à des fins pédagogiques.",
        script=["menu.py"],
	packages=["mitm"]
)
