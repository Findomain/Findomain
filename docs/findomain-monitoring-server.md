# Motivation

Some users do not want to fight with the setup of a monitoring server including database configuration, buying a dedicated VPS, creating cron jobs or systemd timers/services and more. Findomain+ monitoring server is a easy way to get the most of this powerful tool only editing two files: the list of domains to monitor and a configuration file to set up your API keys (optional) and webhooks (required).

# About the Findomain+ server

It is a dedicated VPS hosted in Amazon, this server is specifically designed for subdomains monitoring. There you can modify a `targets.txt` (the domains list to monitor) and `config.toml` (the configuration) files. 

Inside the FTP access you can found a `logs/` folder that contains all the logs for every Findomain+ execution, there is one file per target. When new subdomains are found the old files are renamed to `*.old.txt`, so that you can difference they. We recommmend you to use a FTP client such as [Filezilla](https://filezilla-project.org/) to connect to server.

If your plan has support for screenshots, you can found the images in the `screenshots/` folder inside your home directory.

The frequency of execution is based on your plan starting from every 48 hours in the basic plan.

The server will send you the alerts to the webhook(s) and/or Telegram chat that you have configured previously according to the frequency that you got in your plan.

When you finish your paypment, you will receive an email with the server credentials and documentation about how to fill the configuration file and other details.

# Plans

See [the available plans starting from $5.](https://github.com/Edu4rdSHL/findomain#plans)

# Checkout

[![paypal](https://www.paypalobjects.com/en_US/i/btn/btn_subscribeCC_LG.gif)](https://securityhacklabs.net/findomain.html)
