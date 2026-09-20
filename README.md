<h1 align="center">MC Mod Updater</h1>

<p align="center">
  <img alt="Github top language" src="https://img.shields.io/github/languages/top/Programstor/MC-Mod-Updater?color=56BEB8">
  <img alt="Github language count" src="https://img.shields.io/github/languages/count/Programstor/MC-Mod-Updater?color=56BEB8">
  <img alt="Repository size" src="https://img.shields.io/github/repo-size/Programstor/MC-Mod-Updater?color=56BEB8">
  <img alt="License" src="https://img.shields.io/github/license/Programstor/MC-Mod-Updater?color=56BEB8">
</p>

<p align="center">
  <a href="#dart-about">About</a> &#xa0; | &#xa0; 
  <a href="#sparkles-features">Features</a> &#xa0; | &#xa0;
  <a href="#rocket-setup">Setup</a> &#xa0; | &#xa0;
  <a href="#white_check_mark-requirements">Requirements</a> &#xa0; | &#xa0;
  <a href="#checkered_flag-starting">Starting</a> &#xa0; | &#xa0;
  <a href="https://github.com/Programstor" target="_blank">Author</a>
</p>

<br>

## :dart: About ##

An automated Flask app to update your Minecraft mods with ease. Currently built to add missing functionallity in the Pufferpanel Server Manager.

## :sparkles: Features ##

:heavy_check_mark: Fetch all independent instances from a folder or a Pufferpanel environment;\
:heavy_check_mark: Use the Modrinth API for autonomous version control and mod updating;\
:heavy_check_mark: Discord Webhook integration for automated changelog sending;\
:heavy_check_mark: Secure login page with Pufferpanel OAuth2 Client verification;

## :rocket: Setup ##

The following variables should be either be added to the environment, or added to a file 'pufferpanel.env' in the main folder:

- [SERVERS_DIR] - your instances / minecraft folder (mandatory)

-- Pufferpanel only variables --
- [PANEL_URL] - your Pufferpanel's master URL
- [CLIENT_ID] - your admin OAuth2 client's id
- [CLIENT_SECRET] - your admin OAuth2 client's secret code

## :white_check_mark: Requirements ##

Before starting :checkered_flag:, you need to have a Python environment and libs from the 'requirements.txt'.

## :checkered_flag: Starting ##

On the initial start, a 'data' folder with all found instance data will be crated with each instance having its own .json file.

In the said folder you can:
- Add your own instances in 'instances.json'
- Write some welcome messages for the Discord Webhook in 'welcomes.txt' as an unformatted list (row by row)

After running app.py, the Flask app will be available on <http://localhost:5055>

&#xa0;