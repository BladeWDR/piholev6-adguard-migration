#!/usr/bin/env python3

import zipfile
import yaml
import sys
import os
import tomllib
import sqlite3
import dns.resolver
import socket
from pathlib import Path
from typing import List, Dict, Tuple, Optional
import logging

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

DOMAIN_TYPE_MAPPING = {
    0: {"prefix": "@@|", "suffix": "^$important", "description": "Exact allow"},
    1: {"prefix": "0.0.0.0 ", "suffix": "", "description": "Exact blacklist"},
    2: {"prefix": "@@||", "suffix": "^", "description": "Regex allow"},
    3: {"prefix": "||", "suffix": "^", "description": "Regex blacklist"}
}

class PiHoleExtractor:
    """Handles extraction of data from Pi-hole databases and config files."""
    
    def __init__(self, gravity_db_path: str, pihole_toml_path: str):
        self.gravity_db_path = Path(gravity_db_path)
        self.pihole_toml_path = Path(pihole_toml_path)
    
    def validate_files(self) -> bool:
        if not self.gravity_db_path.exists():
            logger.error(f"Gravity database not found: {self.gravity_db_path}")
            return False
        
        if not self.pihole_toml_path.exists():
            logger.warning(f"Pi-hole TOML config not found: {self.pihole_toml_path}")
        
        return True
    
    def get_adlists(self) -> List[Dict[str, str]]:
        try:
            with sqlite3.connect(self.gravity_db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT address, comment FROM adlist WHERE enabled = 1;')
                results = cursor.fetchall()
                
                return [
                    {'address': address, 'comment': comment or 'No description'}
                    for address, comment in results
                ]
        except sqlite3.Error as e:
            logger.error(f"Database error extracting adlists: {e}")
            return []
    
    def get_domain_rules(self) -> List[Tuple[int, str, str]]:
        """Extract domain rules from gravity database."""
        try:
            with sqlite3.connect(self.gravity_db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT type, domain, comment FROM domainlist WHERE enabled = 1;')
                return cursor.fetchall()
        except sqlite3.Error as e:
            logger.error(f"Database error extracting domains: {e}")
            return []
    
    def get_custom_hosts(self) -> List[Dict[str, str]]:
        if not self.pihole_toml_path.exists():
            return []
        
        try:
            with open(self.pihole_toml_path, "rb") as f:
                toml_data = tomllib.load(f)
                
                hosts_data = []
                if 'dns' in toml_data and 'hosts' in toml_data['dns']:
                    for host_entry in toml_data['dns']['hosts']:
                        parts = host_entry.split()
                        if len(parts) >= 2:
                            hosts_data.append({
                                'domain': parts[1],
                                'ip_address': parts[0]
                            })
                
                return hosts_data
        except Exception as e:
            logger.error(f"Error reading custom hosts: {e}")
            return []
    
    def get_cname_records(self) -> List[Dict[str, str]]:
        if not self.pihole_toml_path.exists():
            return []
        
        try:
            with open(self.pihole_toml_path, "rb") as f:
                toml_data = tomllib.load(f)
                
                cnames_data = []
                if 'dns' in toml_data and 'cnameRecords' in toml_data['dns']:
                    for cname_entry in toml_data['dns']['cnameRecords']:
                        parts = cname_entry.split(',')
                        if len(parts) >= 2:
                            cnames_data.append({
                                'domain': parts[0].strip(),
                                'target': parts[1].strip()
                            })
                
                return cnames_data
        except Exception as e:
            logger.error(f"Error reading CNAME records: {e}")
            return []


class DNSResolver:
    """Handles DNS resolution tasks."""
    
    @staticmethod
    def resolve_to_ip(hostname: str) -> Optional[str]:
        try:
            # Try CNAME first
            try:
                answers = dns.resolver.resolve(hostname, 'CNAME')
                cname_target = str(answers[0].target).rstrip('.')
                logger.info(f"{hostname} is a CNAME for {cname_target}")
                return socket.gethostbyname(cname_target)
            except dns.resolver.NoAnswer:
                # Not a CNAME, try A record
                return socket.gethostbyname(hostname)
        except Exception as e:
            logger.warning(f"Failed to resolve {hostname}: {e}")
            return None


class AdGuardConverter:
    """Converts Pi-hole data to AdGuard Home format."""
    
    @staticmethod
    def convert_adlists(adlists: List[Dict[str, str]]) -> List[Dict[str, any]]:
        return [
            {
                'enabled': True,
                'url': adlist['address'],
                'name': adlist['comment']
            }
            for adlist in adlists
        ]
    
    @staticmethod
    def convert_domain_rules(domain_rules: List[Tuple[int, str, str]]) -> List[str]:
        """Convert Pi-hole domain rules to AdGuard filter rules."""
        converted_rules = []
        
        for rule_type, domain, comment in domain_rules:
            mapping = DOMAIN_TYPE_MAPPING.get(rule_type, {"prefix": "", "suffix": ""})
            rule = f"{mapping['prefix']}{domain}{mapping['suffix']}"
            converted_rules.append(rule)
            
            if comment:
                logger.debug(f"Converted {mapping.get('description', 'unknown')} rule: {domain}")
        
        return converted_rules
    
    @staticmethod
    def convert_custom_hosts(hosts: List[Dict[str, str]]) -> List[Dict[str, str]]:
        return [
            {
                'domain': host['domain'],
                'answer': host['ip_address']
            }
            for host in hosts
        ]
    
    @staticmethod
    def convert_cname_records(cnames: List[Dict[str, str]], resolver: DNSResolver) -> List[Dict[str, str]]:
        rewrites = []
        
        for cname in cnames:
            ip_address = resolver.resolve_to_ip(cname['target'])
            if ip_address:
                rewrites.append({
                    'domain': cname['domain'],
                    'answer': ip_address
                })
            else:
                logger.warning(f"Skipping CNAME {cname['domain']} - could not resolve target")
        
        return rewrites


class FileWriter:
    """Handles writing output files."""
    
    @staticmethod
    def write_yaml(data: List[Dict], filename: str, description: str = "") -> None:
        """Write data to YAML file."""
        try:
            with open(filename, 'w') as f:
                if description:
                    f.write(f"# {description}\n")
                yaml.dump(data, f, default_flow_style=False, indent=2, sort_keys=False)
            logger.info(f"✓ {description or 'Data'} written to {filename}")
        except Exception as e:
            logger.error(f"Error writing {filename}: {e}")
    
    @staticmethod
    def write_text_lines(lines: List[str], filename: str, description: str = "", header: str = "") -> None:
        """Write lines to text file."""
        try:
            with open(filename, 'w') as f:
                if header:
                    f.write(f"{header}\n\n")
                for line in lines:
                    f.write(f"{line}\n")
            logger.info(f"✓ {description or 'Data'} written to {filename}")
        except Exception as e:
            logger.error(f"Error writing {filename}: {e}")


class ConversionOrchestrator:
    """Orchestrates the entire migration process."""
    
    def __init__(self, gravity_db_path: str = './etc/pihole/gravity.db', 
                 pihole_toml_path: str = './etc/pihole/pihole.toml'):
        self.extractor = PiHoleExtractor(gravity_db_path, pihole_toml_path)
        self.converter = AdGuardConverter()
        self.writer = FileWriter()
        self.resolver = DNSResolver()
    
    def run_migration(self) -> bool:
        logger.info("Starting Pi-hole to AdGuard Home migration...")
        
        if not self.extractor.validate_files():
            return False
        
        success = True
        
        # Process adlists
        success &= self._process_adlists()
        
        # Process domain rules
        success &= self._process_domain_rules()
        
        # Process custom DNS entries
        success &= self._process_custom_dns()
        
        # Process CNAME records
        success &= self._process_cnames()
        
        if success:
            logger.info("Conversion completed successfully!")
            self._print_instructions()
        else:
            logger.warning("Conversion completed with some errors.")
        
        return success
    
    def _process_adlists(self) -> bool:
        logger.info("Processing adlists...")
        adlists = self.extractor.get_adlists()
        if not adlists:
            logger.warning("No adlists found")
            return True
        
        converted = self.converter.convert_adlists(adlists)
        self.writer.write_yaml(
            converted, 
            'adlists.yaml', 
            f'AdGuard Home blocklists ({len(converted)} entries)'
        )
        return True
    
    def _process_domain_rules(self) -> bool:
        logger.info("Processing domain rules...")
        rules = self.extractor.get_domain_rules()
        if not rules:
            logger.warning("No domain rules found")
            return True
        
        converted = self.converter.convert_domain_rules(rules)
        self.writer.write_text_lines(
            converted,
            'custom_filters.txt',
            f'Custom filtering rules ({len(converted)} rules)',
            'Add these under Custom Filtering Rules in the AdGuard Home UI.'
        )
        return True
    
    def _process_custom_dns(self) -> bool:
        logger.info("Processing custom DNS entries...")
        hosts = self.extractor.get_custom_hosts()
        cnames = self.extractor.get_cname_records()
        
        # Combine both custom hosts and resolved CNAMEs into one file
        all_rewrites = []
        
        if hosts:
            host_rewrites = self.converter.convert_custom_hosts(hosts)
            all_rewrites.extend(host_rewrites)
            logger.info(f"Found {len(host_rewrites)} custom DNS entries")
        
        if cnames:
            cname_rewrites = self.converter.convert_cname_records(cnames, self.resolver)
            all_rewrites.extend(cname_rewrites)
            logger.info(f"Resolved {len(cname_rewrites)} CNAME records")
        
        if all_rewrites:
            self.writer.write_yaml(
                all_rewrites,
                'dns_rewrites.yaml',
                f'DNS rewrites ({len(all_rewrites)} total entries)'
            )
        else:
            logger.info("No custom DNS entries or CNAME records found")
        
        return True
    
    def _process_cnames(self) -> bool:
        return True
    
    def _print_instructions(self) -> None:
        print("\n" + "="*60)
        print("CONVERSION COMPLETE - Next Steps:")
        print("="*60)
        print("Next Steps:")
        print("="*60)
        print("1. Stop AdGuardHome with AdGuardHome -s stop")
        print("2. Copy the contents of adlists.yaml into AdGuardHome.yaml under 'filters'")
        print("4. custom_dns.yaml and dns_rewrites.yaml should both be copied into AdGuardHome.yaml under the 'rewrites' key.")
        print("5. Start up AdGuardHome again with AdGuardHome -s start")
        print("3. Copy rules from custom_filters.txt to Custom Filtering Rules")
        print("="*60)


def extract_from_backup(backup_path: str, extract_dir: str = "./pihole_backup") -> Tuple[str, str]:
    try:
        with zipfile.ZipFile(backup_path, 'r') as zip_ref:
            zip_ref.extractall(extract_dir)
        
        gravity_db = os.path.join(extract_dir, 'etc/pihole/gravity.db')
        pihole_toml = os.path.join(extract_dir, 'etc/pihole/pihole.toml')
        
        logger.info(f"Backup extracted to {extract_dir}")
        return gravity_db, pihole_toml
    except Exception as e:
        logger.error(f"Error extracting backup: {e}")
        raise


def main():
    if len(sys.argv) > 1:
        # If backup zip provided, extract it first
        backup_path = sys.argv[1]
        if backup_path.endswith('.zip'):
            logger.info(f"Extracting backup from {backup_path}")
            gravity_db, pihole_toml = extract_from_backup(backup_path)
            migrator = ConversionOrchestrator(gravity_db, pihole_toml)
        else:
            logger.error("Please provide a .zip backup file")
            sys.exit(1)
    else:
        # Use default paths
        migrator = ConversionOrchestrator()
    
    success = migrator.run_migration()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
