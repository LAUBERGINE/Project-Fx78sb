import discord
from dotenv import load_dotenv
import os
from random import *
from discord.ext import commands
import datetime
from annexe import *
from discord_slash import *
from discord_slash.utils.manage_commands import create_option, create_choice
from discord_slash.model import SlashCommandOptionType

load_dotenv()

intents = discord.Intents.all()
client = commands.Bot(command_prefix = "!", intents = discord.Intents.all() ,description = "Project Fx78sb")
slash = SlashCommand(client, sync_commands = True)

@client.event
async def on_ready():
    myDate = datetime.datetime.now()
    print( "["+ myDate.strftime("%c") + "] The Bot start !")

@slash.slash(
    name="isvirus",
    guild_ids=[930944345069223957],
    description="Check if a file hash is associated with a virus",
    options=[create_option(name="hash", description="SHA-256, SHA-1, MD5, ...", option_type=3, required=True)]
)
async def IsVirus(ctx: SlashContext, hash):

    result_hash = await get_vt_reputation(hash)
    await ctx.send(embed=result_hash)

@slash.slash(
    name="ipinfo",
    guild_ids=[930944345069223957],
    description="Information on this IP",
    options=[create_option(name="ip", description="IPv4", option_type=SlashCommandOptionType.STRING, required=True)]
)
async def IpInfo(ctx: SlashContext, ip: str):
    try:
        result_location = await get_location(ip)
        await ctx.send(embed=result_location)
    except discord.errors.NotFound as not_found_error:
        print(f"Interaction not found error: {not_found_error}")
    except Exception as e:
        print(f"An error occurred: {e}")
        error_embed = discord.Embed(color=discord.Color.red(), title="Error", description=str(e))
        await ctx.send(embed=error_embed)

@slash.slash(
    name="domaininfo",
    guild_ids=[930944345069223957],
    description="Check the reputation of this domain",
    options=[create_option(name="domain", description="exemple.fr", option_type=3, required=True)]
)
async def DomainInfo(ctx: SlashContext, domain):

    result_domain = await get_domain_reputation(domain)
    await ctx.send(embed=result_domain)

@slash.slash(
    name="genpass",
    guild_ids=[930944345069223957],
    description="Generator of password",
    options=[create_option(name="longeur", description="Nombre de characteres du mot de passe", option_type=4, required=True)]
)
async def MotdepasseGen(ctx: SlashContext, longeur):

    result_gen = generer_mot_de_passe(longeur)
    await ctx.send(f"**Le mot de passe généré est :** `{result_gen}`")

@slash.slash(
    name="passisok",
    guild_ids=[930944345069223957],
    description="Check if this password is OK",
    options=[create_option(name="mdp", description="M0tDEPasse?", option_type=3, required=True)]
)
async def EvaluationPass(ctx: SlashContext, mdp):

    result_eva = evaluation_mot_de_passe(mdp)
    await ctx.send(f"**{result_eva}**")

@slash.slash(
    name="adressmac",
    guild_ids=[930944345069223957],
    description="Check the constructor",
    options=[create_option(name="mac", description="11:11:11:11:11:11", option_type=3, required=True)]
)
async def AdressMac(ctx: SlashContext, mac):

    result_mac = get_mac_info(mac)
    await ctx.send(f"{result_mac}")
    
client.run(os.getenv("TOKEN"))