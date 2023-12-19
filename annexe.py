import os
import discord
from dotenv import load_dotenv
from discord.ext import commands
import requests
import whois
import socket
import string
import random

load_dotenv()

VT_API_KEY = os.getenv("TOKEN_VIRUSTOTAL")

async def get_vt_reputation(file_hash):
    try:
        response = requests.get(f"https://www.virustotal.com/vtapi/v2/file/report?apikey={VT_API_KEY}&resource={file_hash}")
        data = response.json()
        if data['response_code'] == 0:
            nobddEmbed = discord.Embed(colour=discord.Colour.dark_orange(), title='HASH INCONNU')
            nobddEmbed.add_field(name="**Hash du Fichier**", value=f"{file_hash}", inline=False)
            nobddEmbed.add_field(name="**Explication**", value="Nous utilisons la base de donnée de Virus Total, ce Hash n'as pas était reperctorié", inline=False)
            return nobddEmbed
        else:
            positives = data['positives']
            first_result = list(data["scans"].values())[0]["result"]

            if positives < 1:
                nopositiveEmbed = discord.Embed(colour=discord.Colour.green(), title='🟢 AUCUNE MENACE DETECTE 🟢')
                nopositiveEmbed.add_field(name="**Hash du Fichier**", value=f"{file_hash}", inline=False)
                nopositiveEmbed.add_field(name="**Nombre de détections**", value=f"{positives}", inline=False)
                return nopositiveEmbed
            else:
                positiveEmbed = discord.Embed(colour=discord.Colour.red(), title='<:attention:1177283902558191716> FICHIER MALVEILLANT <:attention:1177283902558191716>')
                positiveEmbed.add_field(name="**Nom du fichier**", value=f"**{first_result}**", inline=False)
                positiveEmbed.add_field(name="**Hash du Fichier**", value=f"{file_hash}", inline=False)
                positiveEmbed.add_field(name="**Nombre de détections**", value=f"{positives}", inline=False)
                return positiveEmbed
    except Exception as e:
        print(f"Une erreur s'est produite: {e}")


async def get_location(ip_address):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}")
        data = response.json()
        domain_name = get_domain_from_ip(ip_address)

        if data['status'] == 'success':
            whereipEmbed = discord.Embed(colour=discord.Colour.purple(), title='Adresse IP')
            whereipEmbed.add_field(name="**IP**", value=f"**{data['query']}**", inline=False)
            whereipEmbed.add_field(name="**NOM**", value=f"{data['org']}", inline=False)
            whereipEmbed.add_field(name="**PAYS**", value=f"{data['country']}", inline=False)
            whereipEmbed.add_field(name="**REGION**", value=f"{data['regionName']}", inline=False)
            whereipEmbed.add_field(name="**CODE POSTAL**", value=f"{data['zip']}", inline=False)
            whereipEmbed.add_field(name="**VILLE**", value=f"{data['city']}", inline=False)
            whereipEmbed.add_field(name="**DOMAINE**", value=f"{domain_name}", inline=False)
            return whereipEmbed
        else:
            nowhereipEmbed = discord.Embed(colour=discord.Colour.dark_red(), title='La requête a échoué')
            nowhereipEmbed.add_field(name="**STATUS**", value=f"**{data['status']}**", inline=False)
            return nowhereipEmbed
    except Exception as e:
        ErrorEmbed = discord.Embed(colour=discord.Colour.dark_red(), title='ERROR')
        ErrorEmbed.add_field(name="**ERROR**", value=f"**Une erreur s'est produite: {e}**", inline=False)
        return ErrorEmbed


async def get_domain_reputation(domain):
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {'x-apikey': VT_API_KEY}
        response = requests.get(url, headers=headers)
        domain_info = whois.whois(domain)
        
        if response.status_code == 200:
            data = response.json()

            sympa = data['data']['attributes']['last_analysis_stats']['harmless']
            malveillant = data['data']['attributes']['last_analysis_stats']['malicious']
            undetected = data['data']['attributes']['last_analysis_stats']['undetected']

            creation_date = format_date(domain_info.creation_date)
            expiration_date = format_date(domain_info.expiration_date)
            ip = get_ip_from_domain(domain)

            DomainEmbed = discord.Embed(title=f"INFO SUR LE DOMAIN `{domain}`",color=discord.Color.blue())
            DomainEmbed.add_field(name="**IP**", value=f"{ip}", inline=False)
            DomainEmbed.add_field(name="**HEBERGEUR**", value=f"{domain_info.registrar}", inline=False)
            DomainEmbed.add_field(name="**DATE DE CREATION**", value=f"{creation_date}", inline=True)
            DomainEmbed.add_field(name="**DATE D'EXPIRATION**", value=f"{expiration_date}", inline=True)
            DomainEmbed.add_field(name="**SERVEURS**", value=f"{', '.join(domain_info.name_servers)}", inline=False)
            DomainEmbed.add_field(name="**REPUTATION DU DOMAIN**", value="", inline=False)
            DomainEmbed.add_field(name="SYMPA", value=sympa, inline=True)
            DomainEmbed.add_field(name="MALVEILLANT", value=malveillant, inline=True)
            DomainEmbed.add_field(name="NON DETECTE", value=undetected, inline=True)

            return DomainEmbed
        else:
            noDomainEmbed = discord.Embed(colour=discord.Colour.dark_red(), title='La requête a échoué')
            noDomainEmbed.add_field(name="**STATUS**", value=f"**{response.status_code}**", inline=False)
            return noDomainEmbed
    except Exception as e:
        ErrorEmbed = discord.Embed(colour=discord.Colour.dark_red(), title='ERROR')
        ErrorEmbed.add_field(name="**ERROR**", value=f"**Une erreur s'est produite: {e}**", inline=False)
        return ErrorEmbed

def format_date(date):
    if isinstance(date, list):
        date = date[0] 
    if date is not None:
        return date.strftime('%Y-%m-%d %H:%M:%S')
    else:
        return "N/A"

def get_domain_from_ip(ip_address):
    try:
        domain_name, _, _ = socket.gethostbyaddr(ip_address)
        return domain_name
    except socket.herror as e:
        return f"🟥"
    
def get_ip_from_domain(domain_name):
    try:
        ip_address = socket.gethostbyname(domain_name)
        return ip_address
    except socket.gaierror as e:
        return f"🟥"
    
def generer_mot_de_passe(longueur=12):
    caracteres = string.ascii_letters + string.digits + "+-*!?&@#$"
    
    while True:
        mot_de_passe = ''.join(random.choice(caracteres) for _ in range(longueur))
        if any(c.isupper() for c in mot_de_passe) and any(c.islower() for c in mot_de_passe) \
                and any(c.isdigit() for c in mot_de_passe) and any(c in "+-*!?" for c in mot_de_passe):
            return mot_de_passe
        
def evaluation_mot_de_passe(mot_de_passe):

    if len(mot_de_passe) < 10:
        return "Le mot de passe est trop court."

    if not any(c.isupper() for c in mot_de_passe):
        return "Le mot de passe doit contenir au moins une lettre majuscule."

    if not any(c.islower() for c in mot_de_passe):
        return "Le mot de passe doit contenir au moins une lettre minuscule."

    if not any(c.isdigit() for c in mot_de_passe):
        return "Le mot de passe doit contenir au moins un chiffre."

    caractere_special = set("!@#$%^&*(),.?\":{}|<>")
    if not any(c in caractere_special for c in mot_de_passe):
        return "Le mot de passe doit contenir au moins un caractère spécial."

    return "Le mot de passe semble etre bon !"

def get_mac_info(mac_address):
    api_url = f"https://api.macvendors.com/{mac_address}"
    
    try:
        response = requests.get(api_url)
        if response.status_code == 200:
            return f"**Le constructeur est :** {response.text}"
        else:
            return f"Error **{response.status_code}** l'adresse n'existe pas"
    except requests.exceptions.RequestException as e:
        return f"Error {e}"