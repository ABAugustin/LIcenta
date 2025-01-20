import os
import threading
import socket
from OpenSSL import crypto
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import random
import subprocess
from RSA import *
from cryptography import x509
from cryptography.x509.oid import NameOID, ObjectIdentifier
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from datetime import datetime, timedelta
from RSA import *
import re
from cryptography.hazmat.primitives.asymmetric import padding
import struct

server_ip="207.180.196.203"
server_port=1232
cert_dir="/home/augu/Documents/GitHub/LIcenta/LicentaClient1/Certificates"

# Prime and generator as specified in RFC 3526, 2048-bit MODP Group #14
p_dh = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
           "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD", 16)
g_dh = 2  # The generator for this group is typically 2



# global data for now
server_prt = 1232
cert_file_greeting = "greeting_certificate.crt"

words = ["adolescent", "aftershock", "allegiance", "alteration", "appetizing", "arithmetic", "attractive",
 "background", "ballistics", "befriended", "befuddling", "biographer", "birthplace", "blossoming",
 "breakpoint", "campaigner", "celebrated", "cerebellum", "challenger", "charitable", "chronicled",
 "circuitous", "clarifying", "classmates", "classrooms", "cleansable", "coagulated", "colleagues",
 "commanders", "compassion", "compendium", "compressor", "conceptual", "condiments", "confidants",
 "confounded", "congruence", "connective", "consistent", "consonants", "conspiring", "convection",
 "correcting", "countdowns", "creativity", "cultivated", "daylighted", "deactivate", "dedication",
 "definitely", "delicately", "derivative", "detachment", "developing", "disavowing", "disclosure",
 "disconcert", "dispatcher", "dispensary", "distancing", "distilling", "divergence", "documented",
 "earthquake", "ecological", "efficiency", "electronic", "elementary", "eliminator", "encryption",
 "endeavored", "energizing", "engagement", "enterprise", "enthusiasm", "evaluation", "explaining",
 "expressive", "fascinated", "fertilizer", "flashbacks", "foreshadow", "formidable", "foundation",
 "galvanized", "generation", "gravitated", "headlights", "illustrate", "imaginable", "immaculate",
 "impressive", "indicating", "infraction", "innovative", "instructor", "integrated", "interacted",
 "intercepts", "invaluable", "irrigation", "journalism", "journalist", "justifying", "landscapes",
 "leadership", "legitimate", "logarithms", "mainstream", "manifestos", "mastermind", "memorizing",
 "messengers", "mindreader", "narrations", "networking", "nomination", "noticeable", "objectives",
 "overcoming", "overshadow", "painkiller", "paramedics", "parenthood", "perceptive", "permission",
 "photograph", "playground", "positioned", "precarious", "preference", "preventive", "procedural",
 "processing", "profitable", "projecting", "protesting", "quarantine", "questioned", "rationally",
 "recharging", "reclaiming", "recounting", "redemption", "refreshing", "relaxation", "remembered",
 "repetition", "resilience", "resistance", "restraints", "retirement", "rigorously", "scattering",
 "schoolwork", "separating", "simplistic", "sophomores", "specialist", "speculated", "stabilized",
 "stalwartly", "structured", "submarines", "succeeding", "superhuman", "supervised", "supplement",
 "sustenance", "sympathize", "syndicated", "systematic", "tangential", "terrifying", "thoughtful",
 "thresholds", "tolerating", "tremendous", "triumphant", "uncovering", "unhindered", "veneration",
 "vindicated", "vulnerable", "weathering", "weightless", "wonderland", "workplaces"]


