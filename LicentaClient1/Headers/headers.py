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


# Prime and generator as specified in RFC 3526, 2048-bit MODP Group #14
p_dh = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
           "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD", 16)
g_dh = 2  # The generator for this group is typically 2



# global data for now
server_prt = 1232
cert_file_greeting = "greeting_certificate.crt"

words = [
    "adventure", "adolescent", "aftershock", "allegiance", "alteration", "amazement", "anchoring",
    "animation", "appetizing", "arithmetic", "attractive", "background", "ballistics", "befriended",
    "befuddling", "biographer", "birthplace", "blossoming", "boyfriend", "breakpoint", "broadcast",
    "bulletproof", "campaigner", "celebrated", "cerebellum", "challenger", "charitable", "chronicled",
    "circuitous", "clarifying", "classmates", "classrooms", "cleansable", "coagulated", "collapsing",
    "colleagues", "commanders", "communicate", "compassion", "compendium", "compressor", "conceptual",
    "condiments", "confidants", "confounded", "congruence", "connective", "consistent", "consonants",
    "conspiring", "convection", "converter", "correcting", "countdowns", "countryside", "creativity",
    "cultivated", "curiosity", "dangerous", "daylighted", "deactivate", "dedication", "definitely",
    "delicately", "derivative", "detachment", "developing", "dictionaries", "differentiated", "dimensional",
    "directive", "disavowing", "disclosure", "disconcert", "disentangle", "dispatcher", "dispensary",
    "distancing", "distilling", "distributed", "divergence", "documented", "downloading", "duplication",
    "earthquake", "ecological", "efficiency", "electronic", "elementary", "eliminator", "emergences",
    "empowerful", "enchanting", "encryption", "endeavored", "energizing", "engagement", "enhancement",
    "enlightens", "enrichable", "enrichment", "entangling", "enterprise", "enthusiasm", "evaluation",
    "evolution", "explaining", "expressive", "facilitator", "fascinated", "fertilizer", "firefighter",
    "flashbacks", "foreshadow", "formidable", "formation", "foundation", "framework", "friendship",
    "galvanized", "generation", "gravitated", "haphazard", "headlights", "heartbeats", "highlander",
    "highlight", "hospitable", "houseplant", "illustrate", "imaginable", "immaculate", "immigrants",
    "impressive", "indicating", "infraction", "innovative", "installing", "instructor", "insulating",
    "integrated", "interacted", "intercepts", "interesting", "intertwine", "invaluable", "irrigation",
    "journalism", "journalist", "justifying", "landscapes", "leadership", "legislation", "legitimate",
    "literature", "logarithms", "mainstream", "manifestos", "marketing", "mastermind", "mathematics",
    "memorizing", "messengers", "mindreader", "mountainous", "multiplying", "narrations", "negotiate",
    "networking", "nomination", "noticeable", "nutrition", "objectives", "observation", "obtainable",
    "operation", "optimistic", "outpouring", "overcoming", "overgrowing", "overshadow", "overshooting",
    "overturned", "painkiller", "paramedics", "parenthood", "partnership", "perceptive", "performance",
    "permission", "persistence", "persuading", "photograph", "playground", "positioned", "precarious",
    "preference", "preventive", "pricemaker", "procedural", "processing", "profitable", "projecting",
    "protesting", "providence", "quarantine", "questioned", "rationally", "recharging", "reclaiming",
    "recounting", "redemption", "refinanced", "refreshing", "regenerating", "relaxation", "remembered",
    "repetition", "resilience", "resistance", "restraints", "retirement", "retribution", "retrograde",
    "righteous", "rigorously", "sanctified", "satisfaction", "scattering", "schoolwork", "sculptural",
    "selectable", "separating", "shortcoming", "simplistic", "slaughter", "sophomores", "sorrowful",
    "specialist", "speculated", "stabilized", "stalwartly", "standardize", "stationary", "stratified",
    "structured", "submarines", "succeeding", "superhuman", "supervised", "supplement", "sustenance",
    "sympathize", "syndicated", "systematic", "tangential", "tantalized", "terrifying", "thickness",
    "thoughtful", "thresholds", "tolerating", "totalities", "traditional", "transform", "transfusion",
    "transgress", "transports", "tremendous", "triumphant", "uncovering", "unfoldment", "unhindered",
    "unification", "unobtrusive", "unraveling", "upliftment", "vacational", "veneration", "vicariously",
    "vindicated", "vulnerable", "waterproof", "weathering", "weightless", "wholesome", "withholding",
    "wonderland", "workplaces", "worshiping", "yesterdays"
]
