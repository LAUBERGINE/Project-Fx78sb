import discord
from dotenv import load_dotenv
import os
from random import *
from discord.ext import commands
import datetime
from annexe import *
from discord_slash import *
from discord_slash.utils.manage_commands import create_option, create_choice

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

    result = await get_vt_reputation(hash)
    await ctx.send(embed=result)

@slash.slash(
    name="whereip",
    guild_ids=[930944345069223957],
    description="Check where is this ip",
    options=[create_option(name="ip", description="IPV4", option_type=3, required=True)]
)
async def WhereIp(ctx: SlashContext, ip):

    result = await get_location(ip)
    await ctx.send(embed=result)

@slash.slash(
    name="domaininfo",
    guild_ids=[930944345069223957],
    description="Check the reputation of this domain",
    options=[create_option(name="domain", description="exemple.fr", option_type=3, required=True)]
)
async def DomainInfo(ctx: SlashContext, domain):

    result = await get_domain_reputation(domain)
    await ctx.send(embed=result)
    
client.run(os.getenv("TOKEN"))