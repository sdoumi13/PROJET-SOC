"""
Charge la base MITRE ATT&CK depuis le dépôt officiel
"""
import json
import requests
import pandas as pd
from pathlib import Path

def download_mitre_attack():
    """Télécharge la base MITRE ATT&CK Enterprise"""
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    
    print("📥 Téléchargement MITRE ATT&CK...")
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    
    data = response.json()
    print(f"✅ {len(data['objects'])} objets chargés")
    
    return data

def create_mitre_db():
    """Crée une base MITRE simplifiée pour le SOC"""
    data = download_mitre_attack()
    
    techniques = []
    
    for obj in data['objects']:
        if obj['type'] == 'attack-pattern':
            # Récupère les informations de base
            technique_id = obj.get('external_references', [{}])[0].get('external_id', 'N/A')
            name = obj.get('name', 'Unknown')
            description = obj.get('description', '')
            
            # Récupère les tactiques
            kill_chain = obj.get('kill_chain_phases', [])
            tactics = [phase['phase_name'].replace('-', ' ').title() for phase in kill_chain]
            
            # Patterns de détection basés sur le nom et la description
            patterns = generate_patterns(name, description)
            
            for tactic in tactics if tactics else ['Unknown']:
                techniques.append({
                    'technique': technique_id,
                    'name': name,
                    'tactique': tactic,
                    'description': description[:200] + '...' if len(description) > 200 else description,
                    'patterns': patterns
                })
    
    df = pd.DataFrame(techniques)
    
    # Filtre les techniques pertinentes pour notre SOC
    relevant = df[df['technique'].isin([
        'T1110', 'T1110.001', 'T1110.002', 'T1110.003',  # Brute Force
        'T1046',  # Network Service Scanning
        'T1190',  # Exploit Public-Facing Application
        'T1595', 'T1595.001', 'T1595.002',  # Active Scanning
        'T1040',  # Network Sniffing
        'T1071', 'T1071.001',  # Application Layer Protocol
        'T1133',  # External Remote Services
        'T1078',  # Valid Accounts
        'T1021', 'T1021.004',  # Remote Services - SSH
        'T1498', 'T1499',  # DoS
        'T1203',  # Exploitation for Client Execution
        'T1210',  # Exploitation of Remote Services
    ])]
    
    # Ajoute des patterns personnalisés pour notre environnement
    pattern_mapping = {
        'T1110': 'failed password|authentication failure|invalid user|brute.?force',
        'T1110.001': 'password spray|multiple failed logins',
        'T1110.002': 'password crack|hash crack',
        'T1046': 'nmap|masscan|port.?scan|service.?scan',
        'T1190': 'exploit|fuzzing|dirb|gobuster|nikto|sqlmap',
        'T1595': 'scanning|reconnaissance|probe',
        'T1071': 'http|https|dns query|web request',
        'T1021.004': 'ssh|sshd|port 22',
        'T1498': 'flood|dos|ddos|syn flood',
        'T1203': 'buffer overflow|code execution|exploit',
    }
    
    relevant['patterns'] = relevant['technique'].map(
        lambda x: pattern_mapping.get(x, pattern_mapping.get(x.split('.')[0], ''))
    )
    
    return relevant

def generate_patterns(name, description):
    """Génère des patterns de détection basiques"""
    keywords = []
    
    # Mots-clés du nom
    name_lower = name.lower()
    if 'brute' in name_lower:
        keywords.append('brute.?force|failed.?password')
    if 'scan' in name_lower:
        keywords.append('scan|nmap|masscan')
    if 'exploit' in name_lower:
        keywords.append('exploit|vulnerability')
    if 'password' in name_lower:
        keywords.append('password|credential')
    
    return '|'.join(keywords) if keywords else 'suspicious'

if __name__ == '__main__':
    print("🔧 Création de la base MITRE pour le SOC...")
    
    df = create_mitre_db()
    
    output_path = Path('data/mitre_db.csv')
    output_path.parent.mkdir(exist_ok=True)
    
    df.to_csv(output_path, index=False)
    
    print(f"✅ Base MITRE créée : {len(df)} techniques")
    print(f"📁 Sauvegardée dans : {output_path}")
    print("\n📊 Aperçu :")
    print(df[['technique', 'name', 'tactique']].head(10))