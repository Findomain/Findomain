# Motivation

Some users do not want to fight with the setup of a monitoring server including database configuration, buying a dedicated VPS, creating cron jobs or systemd timers/services and more. Findomain+ monitoring server is a easy way to get the most of this powerful tool only editing two files: the list of domains to monitor and a configuration file to set up your API keys (optional) and webhooks (required).

# About the Findomain+ server

Findomain+ monitoring server that is included in the tiers from Findomain+ VIP Patron onwards is a dedicated VPS hosted in Amazon, this server is specifically designed for subdomains monitoring. When you got a tier equal or major to Findomain+ VIP you got access to this server where you can modify a `targets.txt` (the domains list to monitor) and `config.toml` (the configuration) files using a FTP server such as [Filezilla](https://filezilla-project.org/).

When you configure it, a systemd timer is launched and start the monitoring process for new subdomains according to your configuration file, the frequency is based on your tier as well starting from every 30 hours.

The server will send you the alerts to the webhook(s) you have configured previously according to the frequency that you got in your tier.
