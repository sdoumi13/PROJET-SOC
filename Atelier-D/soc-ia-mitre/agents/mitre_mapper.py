"""
MITRE ATT&CK Mapper
Mappe les événements de sécurité sur les techniques MITRE ATT&CK
"""
import re
import pandas as pd
from pathlib import Path
from typing import Dict, List
import json

class MitreMapper:
    def __init__(self, mitre_db_path: str = 'data/mitre_db.csv'):
        """
        Initialise le mapper MITRE
        
        Args:
            mitre_db_path: Chemin vers la base de données MITRE locale
        """
        self.db_path = Path(mitre_db_path)
        self.db = None
        self.technique_cache = {}
        self.statistics = {
            'total_mappings': 0,
            'techniques_detected': set(),
            'tactics_detected': set()
        }
        
        self._load_database()
    
    def _load_database(self):
        """Charge la base de données MITRE"""
        if not self.db_path.exists():
            print(f"⚠️ Base MITRE non trouvée: {self.db_path}")
            print("Création d'une base minimale...")
            self._create_minimal_database()
        
        try:
            self.db = pd.read_csv(self.db_path)
            print(f"✅ Base MITRE chargée: {len(self.db)} techniques")
        except Exception as e:
            print(f"❌ Erreur chargement MITRE: {e}")
            self._create_minimal_database()
    
    def _create_minimal_database(self):
        """Crée une base MITRE minimale pour les tests"""
        minimal_data = [
            {
                'technique': 'T1110',
                'name': 'Brute Force',
                'tactique': 'Credential Access',
                'description': 'Adversaries may use brute force techniques to gain access to accounts',
                'patterns': 'failed password|authentication failure|invalid user|brute.?force|hydra'
            },
            {
                'technique': 'T1110.001',
                'name': 'Password Guessing',
                'tactique': 'Credential Access',
                'description': 'Adversaries may use password guessing to gain access',
                'patterns': 'failed password|invalid password|password guess'
            },
            {
                'technique': 'T1110.003',
                'name': 'Password Spraying',
                'tactique': 'Credential Access',
                'description': 'Adversaries may use password spraying attacks',
                'patterns': 'multiple failed logins|password spray|many authentication attempts'
            },
            {
                'technique': 'T1046',
                'name': 'Network Service Scanning',
                'tactique': 'Discovery',
                'description': 'Adversaries may attempt to get a listing of services running on remote hosts',
                'patterns': 'nmap|masscan|port.?scan|service.?scan|network scan'
            },
            {
                'technique': 'T1190',
                'name': 'Exploit Public-Facing Application',
                'tactique': 'Initial Access',
                'description': 'Adversaries may attempt to exploit vulnerabilities in public-facing applications',
                'patterns': 'exploit|fuzzing|dirb|gobuster|nikto|sqlmap|dirbuster|wfuzz'
            },
            {
                'technique': 'T1595',
                'name': 'Active Scanning',
                'tactique': 'Reconnaissance',
                'description': 'Adversaries may execute active reconnaissance scans',
                'patterns': 'scanning|reconnaissance|probe|fingerprint'
            },
            {
                'technique': 'T1595.001',
                'name': 'Scanning IP Blocks',
                'tactique': 'Reconnaissance',
                'description': 'Adversaries may scan victim IP blocks',
                'patterns': 'ip.?scan|subnet.?scan|network.?sweep'
            },
            {
                'technique': 'T1021.004',
                'name': 'SSH',
                'tactique': 'Lateral Movement',
                'description': 'Adversaries may use SSH for lateral movement',
                'patterns': 'ssh|sshd|port 22|ssh connection'
            },
            {
                'technique': 'T1071.001',
                'name': 'Web Protocols',
                'tactique': 'Command and Control',
                'description': 'Adversaries may use web protocols for C2',
                'patterns': 'http|https|web request|GET|POST'
            },
            {
                'technique': 'T1498',
                'name': 'Network Denial of Service',
                'tactique': 'Impact',
                'description': 'Adversaries may perform DoS attacks',
                'patterns': 'flood|dos|ddos|syn flood|denial of service'
            },
            {
                'technique': 'T1078',
                'name': 'Valid Accounts',
                'tactique': 'Defense Evasion',
                'description': 'Adversaries may obtain and abuse valid accounts',
                'patterns': 'successful login|authenticated|valid credentials'
            },
            {
                'technique': 'T1133',
                'name': 'External Remote Services',
                'tactique': 'Persistence',
                'description': 'Adversaries may leverage external remote services',
                'patterns': 'remote access|vpn|remote desktop|rdp'
            }
        ]
        
        self.db = pd.DataFrame(minimal_data)
        self.db_path.parent.mkdir(exist_ok=True)
        self.db.to_csv(self.db_path, index=False)
        print(f"✅ Base MITRE minimale créée: {len(self.db)} techniques")
    
    def map_event(self, event: Dict) -> List[Dict]:
        """
        Mappe un événement sur les techniques MITRE
        
        Args:
            event: Événement à mapper
            
        Returns:
            Liste de techniques détectées avec scores de confiance
        """
        matches = []
        
        # Contenu à analyser
        message = event.get('message', '').lower()
        event_type = event.get('event_type', '').lower()
        
        # Combine message et type pour analyse
        full_content = f"{message} {event_type}"
        
        # Recherche dans la base
        for _, row in self.db.iterrows():
            patterns = row['patterns'].split('|')
            
            # Compte les patterns qui matchent
            matches_count = 0
            matched_patterns = []
            
            for pattern in patterns:
                if re.search(pattern.strip(), full_content, re.IGNORECASE):
                    matches_count += 1
                    matched_patterns.append(pattern.strip())
            
            # Si au moins un pattern matche
            if matches_count > 0:
                # Score de confiance basé sur le nombre de patterns
                confidence = min(matches_count / len(patterns), 1.0)
                
                technique_info = {
                    'technique_id': row['technique'],
                    'technique_name': row['name'],
                    'tactic': row['tactique'],
                    'description': row['description'],
                    'confidence': float(confidence),
                    'matched_patterns': matched_patterns,
                    'match_count': matches_count,
                    'total_patterns': len(patterns)
                }
                
                matches.append(technique_info)
                
                # Mise à jour des statistiques
                self.statistics['techniques_detected'].add(row['technique'])
                self.statistics['tactics_detected'].add(row['tactique'])
        
        # Tri par confiance décroissante
        matches.sort(key=lambda x: x['confidence'], reverse=True)
        
        self.statistics['total_mappings'] += len(matches)
        
        return matches
    
    def get_kill_chain(self, techniques: List[Dict]) -> List[str]:
        """
        Reconstruit la kill chain à partir des techniques détectées
        
        Returns:
            Liste ordonnée des tactiques (kill chain)
        """
        # Ordre standard de la kill chain MITRE
        kill_chain_order = [
            'Reconnaissance',
            'Resource Development',
            'Initial Access',
            'Execution',
            'Persistence',
            'Privilege Escalation',
            'Defense Evasion',
            'Credential Access',
            'Discovery',
            'Lateral Movement',
            'Collection',
            'Command and Control',
            'Exfiltration',
            'Impact'
        ]
        
        detected_tactics = set(t['tactic'] for t in techniques)
        
        # Retourne les tactiques dans l'ordre de la kill chain
        return [tactic for tactic in kill_chain_order if tactic in detected_tactics]
    
    def generate_attack_narrative(self, techniques: List[Dict], event: Dict) -> str:
        """
        Génère un récit d'attaque basé sur les techniques détectées
        """
        if not techniques:
            return "Aucune technique MITRE détectée."
        
        kill_chain = self.get_kill_chain(techniques)
        
        narrative = f"🎯 Attaque détectée depuis {event.get('src_ip', 'IP inconnue')}\n\n"
        
        if kill_chain:
            narrative += f"📊 Kill Chain: {' → '.join(kill_chain)}\n\n"
        
        narrative += "🔍 Techniques identifiées:\n"
        
        for i, tech in enumerate(techniques[:5], 1):  # Top 5
            narrative += f"\n{i}. {tech['technique_id']} - {tech['technique_name']}\n"
            narrative += f"   Tactique: {tech['tactic']}\n"
            narrative += f"   Confiance: {tech['confidence']*100:.1f}%\n"
            narrative += f"   Patterns: {', '.join(tech['matched_patterns'][:3])}\n"
        
        return narrative
    
    def create_mitre_matrix(self, events: List[Dict]) -> pd.DataFrame:
        """
        Crée une matrice MITRE personnalisée basée sur les événements analysés
        
        Returns:
            DataFrame avec Technique | Tactic | Occurrences | Avg Confidence
        """
        technique_stats = {}
        
        for event in events:
            techniques = self.map_event(event)
            
            for tech in techniques:
                tech_id = tech['technique_id']
                
                if tech_id not in technique_stats:
                    technique_stats[tech_id] = {
                        'technique': tech_id,
                        'name': tech['technique_name'],
                        'tactic': tech['tactic'],
                        'occurrences': 0,
                        'confidences': []
                    }
                
                technique_stats[tech_id]['occurrences'] += 1
                technique_stats[tech_id]['confidences'].append(tech['confidence'])
        
        # Convertit en DataFrame
        matrix_data = []
        for tech_id, stats in technique_stats.items():
            matrix_data.append({
                'technique': stats['technique'],
                'name': stats['name'],
                'tactic': stats['tactic'],
                'occurrences': stats['occurrences'],
                'avg_confidence': sum(stats['confidences']) / len(stats['confidences'])
            })
        
        df = pd.DataFrame(matrix_data)
        
        if not df.empty:
            df = df.sort_values('occurrences', ascending=False)
        
        return df
    
    def export_to_navigator(self, matrix: pd.DataFrame, output_path: str = 'outputs/mitre_navigator.json'):
        """
        Exporte vers le format MITRE ATT&CK Navigator
        
        Format compatible avec: https://mitre-attack.github.io/attack-navigator/
        """
        Path(output_path).parent.mkdir(exist_ok=True)
        
        techniques = []
        
        for _, row in matrix.iterrows():
            # Couleur basée sur le nombre d'occurrences
            score = min(row['occurrences'] / 10, 1.0)  # Normalise à 10 max
            
            techniques.append({
                'techniqueID': row['technique'],
                'score': int(score * 100),
                'color': '',
                'comment': f"Détecté {row['occurrences']} fois avec confiance moyenne de {row['avg_confidence']:.2%}",
                'enabled': True
            })
        
        navigator_layer = {
            'name': 'SOC IA - Détections',
            'versions': {
                'attack': '14',
                'navigator': '4.9.1',
                'layer': '4.5'
            },
            'domain': 'enterprise-attack',
            'description': 'Techniques MITRE ATT&CK détectées par le SOC IA',
            'filters': {
                'platforms': ['Linux', 'Windows', 'macOS', 'Network']
            },
            'sorting': 0,
            'layout': {
                'layout': 'side',
                'aggregateFunction': 'average',
                'showID': True,
                'showName': True
            },
            'hideDisabled': False,
            'techniques': techniques,
            'gradient': {
                'colors': [
                    '#ffffff',
                    '#ffff00',
                    '#ff0000'
                ],
                'minValue': 0,
                'maxValue': 100
            },
            'legendItems': [],
            'metadata': [],
            'showTacticRowBackground': False,
            'tacticRowBackground': '#dddddd',
            'selectTechniquesAcrossTactics': True
        }
        
        with open(output_path, 'w') as f:
            json.dump(navigator_layer, f, indent=2)
        
        print(f"✅ Export Navigator: {output_path}")
        print(f"🌐 Visualiser sur: https://mitre-attack.github.io/attack-navigator/")
    
    def get_statistics(self) -> Dict:
        """Retourne les statistiques de mapping"""
        return {
            'total_mappings': self.statistics['total_mappings'],
            'unique_techniques': len(self.statistics['techniques_detected']),
            'unique_tactics': len(self.statistics['tactics_detected']),
            'techniques_list': list(self.statistics['techniques_detected']),
            'tactics_list': list(self.statistics['tactics_detected'])
        }

if __name__ == '__main__':
    # Test
    mapper = MitreMapper()
    
    # Test avec différents événements
    test_events = [
        {
            'src_ip': '203.0.113.10',
            'event_type': 'ssh_attempt',
            'message': 'Failed password for invalid user admin from 203.0.113.10 port 54321 ssh2'
        },
        {
            'src_ip': '203.0.113.10',
            'event_type': 'port_scan',
            'message': 'nmap -sV -p- 192.168.1.1'
        },
        {
            'src_ip': '198.51.100.50',
            'event_type': 'http_request',
            'message': 'gobuster dir -u http://target.com -w wordlist.txt'
        }
    ]
    
    print("🧪 Test MITRE Mapper\n")
    
    for event in test_events:
        print(f"📝 Événement: {event['message'][:50]}...")
        techniques = mapper.map_event(event)
        
        if techniques:
            print(f"   ✅ {len(techniques)} technique(s) détectée(s):")
            for tech in techniques:
                print(f"      - {tech['technique_id']}: {tech['technique_name']} "
                      f"(confiance: {tech['confidence']*100:.0f}%)")
        else:
            print("   ℹ️ Aucune technique détectée")
        print()
    
    # Test matrice
    print("\n📊 Matrice MITRE:")
    matrix = mapper.create_mitre_matrix(test_events)
    print(matrix.to_string(index=False))
    
    # Export Navigator
    mapper.export_to_navigator(matrix)