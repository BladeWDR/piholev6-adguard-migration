# Migrate from Pihole v6 to Adguard Home

This tool will take a Teleporter export and convert it into Adguard Home style yaml.

## Steps

1. Export your Pihole Teleporter config from settings.
2. Clone this repo.
3. Install PyYAML and requests from pip.

   ```bash
   pip install PyYAML requests
   ```

4. Also make sure you have `dnspython` installed
   ```bash
   sudo apt install python3-dnspython
   ```
5. Run the script.

   ```bash
   python3 migrationtool.py pihole.xxxxxx.zip
   ```

6. The script will dump an adlist.yaml file on disk that you can copy and paste into your AdGuardHome.yaml file. Remember that in order to edit AdGuardHome.yaml you need to stop the service first. `AdGuardHome -s stop`. Once you've pasted in your values and made sure your indentation is right, start it again. `AdGuardHome -s start`
