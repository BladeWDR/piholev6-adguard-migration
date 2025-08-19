# Migrate from Pihole v6 to Adguard Home

This tool will take a Teleporter export and convert it into Adguard Home style yaml (or in the case of allowlists / blocklists, Adblock-style rulesets)

## Steps

1. Export your Pihole Teleporter config from settings.
2. Clone this repo.
3. Install PyYAML from pip.

   ```bash
   pip install PyYAML
   ```

4. Also make sure you have `dnspython` installed
   ```bash
   sudo apt install python3-dnspython
   ```
5. Run the script.

   ```bash
   python3 migrationtool.py pi-hole.xxxxxx.zip
   ```

6. Follow the instructions on screen to update your AdGuardHome.yaml. Once done, start up AdGuardHome again. `AdGuardHome -s start`
7. Lastly, you can import your custom allowlists and blocklists by directly pasting them into the "Custom Filtering Rules" screen on AdGuardHome.
