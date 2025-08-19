import zipfile
import yaml
import sys
import os
import tomllib
from datetime import datetime, timezone
import sqlite3
import dns.resolver
import socket

def extract_adlists(filename):
    with sqlite3.connect(filename) as connection:
        cursor = connection.cursor() 
        adlist_query = 'SELECT address,comment from adlist;'
        cursor.execute(adlist_query)
        all_adlists = cursor.fetchall()

        adlists_data = []
        for address, comment in all_adlists:
            adlists_data.append({
                'address': address,
                'comment': comment
            })
        
        return adlists_data

def write_adlists_to_yaml(filename, output_file):
    adlists = extract_adlists(filename)
    
    yaml_data = []
    for adlist in adlists:
        yaml_data.append({
            'enabled': True,
            'url': adlist['address'],
            'name': adlist['comment']
        })
    
    with open(output_file, 'w') as f:
        yaml.dump(yaml_data, f, default_flow_style=False, indent=2)
    
    print(f"Adlists written to {output_file}")
    return yaml_data

def extract_domains(filename):
    with sqlite3.connect(filename) as connection:
        cursor = connection.cursor() 
        adlist_query = 'SELECT type,domain,comment from domainlist;'
        cursor.execute(adlist_query)
        all_domains = cursor.fetchall()

        domains_data = []
        for type_val, domain in all_domains:
            if type_val == 1:
                prefix = r"0.0.0.0 "
                suffix = r""
            elif type_val == 3:
                prefix = r"||"
                suffix = r"^"
            elif type_val == 0:
                prefix = r"@@|"
                suffix = r"^"
            elif type_val == 2:
                prefix = r"@@||"
                suffix = r"^"
            else:
                prefix = ""
                suffix = ""
            domains_data.append(prefix + domain + suffix)

    return domains_data

def write_lines_to_file(filename, data):
    with open(filename, "w") as file:
        for line in data:
            file.write(line + "\n")

# Pihole v6 stores your custom DNS records in its pihole.toml file.
def extract_custom_domains(filename):
    try:
        with open(filename, "rb") as pihole_toml:
            toml_data = tomllib.load(pihole_toml)

            custom_domains_data = []
            
            # Check if the dns.hosts section exists
            if 'dns' in toml_data and 'hosts' in toml_data['dns']:
                hosts_list = toml_data['dns']['hosts']
                
                for host in hosts_list:
                    # need to split on the space since pihole.toml just has them as a TOML list of strings.
                    split_hosts = host.split(' ')
                    if len(split_hosts) >= 2:
                        custom_domains_data.append({
                            'domain': split_hosts[1],
                            'ip_address': split_hosts[0]
                        })
            
            return custom_domains_data
    except FileNotFoundError:
        print(f"Warning: {filename} not found. Skipping custom domains.")
        return []
    except Exception as e:
        print(f"Error reading {filename}: {e}")
        return []

def write_custom_domains_to_file(filename, output_file):
    custom_domains = extract_custom_domains(filename)

    if not custom_domains:
        print("No custom domains found.")
        return

    yaml_data = []
    for domain in custom_domains:
        yaml_data.append({
            'enabled': True,
            'url': domain['domain'],
            'name': domain['ip_address']
        })

    with open(output_file, 'w') as f:
        yaml.dump(yaml_data, f, default_flow_style=False, indent=2)

    print(f"Custom domains written to {output_file}")

def cname_to_ip(hostname):
    try:
        answers = dns.resolver.resolve(hostname, 'CNAME')
        cname_target = str(answers[0].target).rstrip('.')
        print(f"{hostname} is a CNAME for {cname_target}")
        
        ip = socket.gethostbyname(cname_target)
        return ip
    except dns.resolver.NoAnswer:
        # Not a CNAME, try to resolve directly
        try:
            ip = socket.gethostbyname(hostname)
            return ip
        except Exception as e:
            return None
    except Exception as e:
        print(f"Error resolving {hostname}: {e}")
        return None

def extract_custom_cnames(filename, output_file):
    try:
        with open(filename, "rb") as pihole_toml:
            toml_data = tomllib.load(pihole_toml)

            custom_cnames = []

            if 'dns' in toml_data and 'cnameRecords' in toml_data['dns']:
                cnames_list = toml_data['dns']['cnameRecords']

                for host in cnames_list:
                    # for some reason cnames are split using a comma rather than a space.
                    # Who needs consistency?
                    split_hosts = host.split(',')
                    
                    if len(split_hosts) >= 2:
                        # Attempt to resolve the CNAME to the target IP since AdGuard Home doesn't support them.
                        ip_address = cname_to_ip(split_hosts[1].strip())

                        if ip_address is not None:
                            custom_cnames.append({
                                'domain': split_hosts[0].strip(),
                                'ip_address': ip_address
                            })
                        else:
                            print(f'Sorry, was unable to resolve the CNAME {split_hosts[0]}')

            yaml_data = []

            for cname in custom_cnames:
                yaml_data.append({
                    'domain': cname['domain'],
                    'answer': cname['ip_address']
                })

            if yaml_data:
                with open(output_file, 'w') as file:
                    yaml.dump(yaml_data, file, default_flow_style=False, indent=2)

                print(f"Wrote custom CNAMEs to {output_file}")
            else:
                print("No custom CNAMEs found.")
                
    except FileNotFoundError:
        print(f"Warning: {filename} not found. Skipping custom CNAMEs.")
    except Exception as e:
        print(f"Error processing CNAMEs from {filename}: {e}")


def main():
    # This is for later. I want to have it parse the current directory for pihole backup zip files and automatically extract them if it finds one.
    # For now I'm going to just manually tell it where to find the databases so I'm not extracting this zip file 8 billion times. 
    # with zipfile.ZipFile(sys.argv, 'r') as zip_ref:
    #     zip_ref.extractall(cwd)

    gravity_db = './etc/pihole/gravity.db'
    pihole_toml = './etc/pihole/pihole.toml'

    if not os.path.exists(gravity_db):
        print(f"Error: {gravity_db} not found!")
        return

    write_adlists_to_yaml(gravity_db, 'adlists.yaml')

    domains = extract_domains(gravity_db)
    write_lines_to_file('domains.txt', domains)

    if os.path.exists(pihole_toml):
        write_custom_domains_to_file(pihole_toml, 'custom_domains.yaml')

        extract_custom_cnames(pihole_toml, 'rewrites.yaml')
    else:
        print(f"Warning: {pihole_toml} not found. Skipping custom domains and CNAMEs.")


if __name__ == "__main__":
    main()
