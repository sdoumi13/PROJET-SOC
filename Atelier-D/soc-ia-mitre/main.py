"""
Pipeline Principal SOC IA - Intégration complète
Ateliers A + C + D
"""
import json
import sys
from pathlib import Path
from datetime import datetime
from typing import List, Dict

# Import des agents
sys.path.append('agents')
from lm_client import LMClient
from features import FeatureExtractor
from anomaly_detector import AnomalyDetector
from trust_agent import TrustAgent
from mitre_mapper import MitreMapper
from xai_explainer import XAIExplainer

class SOCPipeline:
    def __init__(self):
        """Initialise le pipeline SOC complet"""
        print("🚀 Initialisation du SOC IA...")
        
        # Création des dossiers
        Path('data').mkdir(exist_ok=True)
        Path('outputs').mkdir(exist_ok=True)
        
        # Initialisation des agents
        print("  📡 Chargement LM Client...")
        self.lm_client = LMClient()
        
        print("  🔍 Chargement Anomaly Detector...")
        self.anomaly_detector = AnomalyDetector()
        
        print("  🎯 Chargement Trust Agent...")
        self.trust_agent = TrustAgent(temperature=1.5, threshold=0.7)
        
        print("  🗺️ Chargement MITRE Mapper...")
        self.mitre_mapper = MitreMapper()
        
        print("  💬 Chargement XAI Explainer...")
        self.xai_explainer = XAIExplainer(self.lm_client)
        
        # Statistiques
        self.stats = {
            'total_events': 0,
            'anomalies_detected': 0,
            'alerts_generated': 0,
            'techniques_detected': set(),
            'processing_times': []
        }
        
        # Résultats
        self.results = []
        
        print("✅ SOC IA prêt!\n")
    
    def process_event(self, event: Dict) -> Dict:
        """
        Traite un événement à travers le pipeline complet
        
        Pipeline: anomaly_detector → analyzer → trust_agent → mitre_mapper → xai_explainer
        """
        start_time = datetime.now()
        
        event_id = event.get('id', f"evt_{self.stats['total_events']}")
        event['id'] = event_id
        
        print(f"\n{'='*60}")
        print(f"📨 Traitement événement: {event_id}")
        print(f"   IP: {event.get('src_ip')} | Type: {event.get('event_type')}")
        print(f"{'='*60}")
        
        result = {
            'event': event,
            'pipeline_steps': {}
        }
        
        # ÉTAPE 1: Détection d'anomalie (Atelier C)
        print("\n[1/5] 🔍 Détection d'anomalies...")
        anomaly_score, anomaly_analysis = self.anomaly_detector.detect(event)
        result['anomaly_score'] = anomaly_score
        result['anomaly_analysis'] = anomaly_analysis
        result['pipeline_steps']['anomaly_detection'] = 'completed'
        
        print(f"      Score d'anomalie: {anomaly_score:.3f}")
        print(f"      Prédiction: {anomaly_analysis['prediction']}")
        
        if anomaly_analysis['top_suspicious_features']:
            print(f"      Features suspectes: {len(anomaly_analysis['top_suspicious_features'])}")
        
        # ÉTAPE 2: Analyse LLM
        print("\n[2/5] 🤖 Analyse IA (LLM)...")
        llm_analysis = self.lm_client.analyze_security_event(event)
        result['llm_analysis'] = llm_analysis
        result['pipeline_steps']['llm_analysis'] = 'completed'
        
        print(f"      Malveillant: {llm_analysis['is_malicious']}")
        print(f"      Confiance LLM: {llm_analysis['confidence']:.3f}")
        
        # ÉTAPE 3: Calibration de confiance (Atelier A)
        print("\n[3/5] 🎯 Calibration de confiance...")
        
        # Score heuristique simple basé sur mots-clés
        heuristic_score = self._compute_heuristic_score(event)
        
        trust_score, trust_analysis = self.trust_agent.calibrate_decision(
            llm_confidence=llm_analysis['confidence'],
            anomaly_score=anomaly_score,
            heuristic_score=heuristic_score
        )
        result['trust_score'] = trust_score
        result['trust_analysis'] = trust_analysis
        result['pipeline_steps']['trust_calibration'] = 'completed'
        
        print(f"      Score brut: {trust_analysis['raw_score']:.3f}")
        print(f"      Score calibré: {trust_score:.3f}")
        print(f"      Décision: {'⚠️ ALERTE' if trust_analysis['should_alert'] else '✓ Normal'}")
        
        # ÉTAPE 4: Mapping MITRE (Atelier D)
        print("\n[4/5] 🗺️ Mapping MITRE ATT&CK...")
        mitre_techniques = self.mitre_mapper.map_event(event)
        result['mitre_techniques'] = mitre_techniques
        result['pipeline_steps']['mitre_mapping'] = 'completed'
        
        if mitre_techniques:
            print(f"      Techniques détectées: {len(mitre_techniques)}")
            for tech in mitre_techniques[:3]:
                print(f"        • {tech['technique_id']}: {tech['technique_name']} "
                      f"(conf: {tech['confidence']*100:.0f}%)")
            
            self.stats['techniques_detected'].update(
                t['technique_id'] for t in mitre_techniques
            )
        else:
            print("      Aucune technique MITRE détectée")
        
        # ÉTAPE 5: Explication XAI (Atelier D)
        print("\n[5/5] 💬 Génération explication XAI...")
        explanation = self.xai_explainer.explain(
            event=event,
            mitre_techniques=mitre_techniques,
            anomaly_score=anomaly_score,
            trust_score=trust_score,
            llm_analysis=llm_analysis
        )
        result['explanation'] = explanation
        result['pipeline_steps']['xai_explanation'] = 'completed'
        
        print(f"      Résumé: {explanation['summary']}")
        print(f"      Niveau de menace: {explanation['scores']['threat_level']}")
        
        # Statistiques
        processing_time = (datetime.now() - start_time).total_seconds()
        result['processing_time'] = processing_time
        
        self.stats['total_events'] += 1
        if anomaly_analysis['is_anomaly']:
            self.stats['anomalies_detected'] += 1
        if trust_analysis['should_alert']:
            self.stats['alerts_generated'] += 1
        self.stats['processing_times'].append(processing_time)
        
        print(f"\n⏱️ Temps de traitement: {processing_time:.3f}s")
        
        # Sauvegarde
        self.results.append(result)
        
        return result
    
    def _compute_heuristic_score(self, event: Dict) -> float:
        """Calcule un score heuristique simple"""
        message = event.get('message', '').lower()
        
        # Mots-clés suspects
        bad_keywords = ['failed', 'denied', 'invalid', 'error', 'attack', 
                       'exploit', 'scan', 'unauthorized', 'forbidden']
        
        # Mots-clés normaux
        good_keywords = ['success', 'ok', 'accepted', 'authorized', 'valid']
        
        bad_count = sum(1 for kw in bad_keywords if kw in message)
        good_count = sum(1 for kw in good_keywords if kw in message)
        
        # Score entre 0 et 1
        if bad_count > good_count:
            score = 0.5 + (min(bad_count, 5) / 10)
        else:
            score = 0.5 - (min(good_count, 5) / 10)
        
        return max(0, min(score, 1))
    
    def process_batch(self, events: List[Dict]) -> List[Dict]:
        """Traite un batch d'événements"""
        print(f"\n{'#'*60}")
        print(f"📦 Traitement de {len(events)} événements")
        print(f"{'#'*60}")
        
        results = []
        for event in events:
            try:
                result = self.process_event(event)
                results.append(result)
            except Exception as e:
                print(f"❌ Erreur traitement {event.get('id')}: {e}")
                import traceback
                traceback.print_exc()
        
        return results
    
    def save_results(self, filepath: str = 'outputs/soc_results.json'):
        """Sauvegarde les résultats"""
        output = {
            'timestamp': datetime.now().isoformat(),
            'statistics': {
                'total_events': self.stats['total_events'],
                'anomalies_detected': self.stats['anomalies_detected'],
                'alerts_generated': self.stats['alerts_generated'],
                'unique_techniques': len(self.stats['techniques_detected']),
                'techniques_list': list(self.stats['techniques_detected']),
                'avg_processing_time': sum(self.stats['processing_times']) / 
                                      max(len(self.stats['processing_times']), 1)
            },
            'results': self.results
        }
        
        with open(filepath, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"\n💾 Résultats sauvegardés: {filepath}")
    
    def generate_summary(self):
        """Affiche un résumé des résultats"""
        print(f"\n{'='*60}")
        print("📊 RÉSUMÉ D'EXÉCUTION")
        print(f"{'='*60}")
        print(f"Événements traités: {self.stats['total_events']}")
        print(f"Anomalies détectées: {self.stats['anomalies_detected']}")
        print(f"Alertes générées: {self.stats['alerts_generated']}")
        print(f"Techniques MITRE uniques: {len(self.stats['techniques_detected'])}")
        
        if self.stats['processing_times']:
            avg_time = sum(self.stats['processing_times']) / len(self.stats['processing_times'])
            print(f"Temps moyen de traitement: {avg_time:.3f}s")
        
        print(f"{'='*60}\n")

def load_sample_events() -> List[Dict]:
    """Charge des événements d'exemple pour test"""
    return [
        {
            'timestamp': '2024-01-15T10:23:45Z',
            'src_ip': '203.0.113.10',
            'dst_ip': '192.168.1.1',
            'src_port': 54321,
            'dst_port': 22,
            'event_type': 'ssh_attempt',
            'message': 'Failed password for invalid user admin from 203.0.113.10 port 54321 ssh2'
        },
        {
            'timestamp': '2024-01-15T10:24:12Z',
            'src_ip': '203.0.113.10',
            'dst_ip': '192.168.1.1',
            'src_port': 54322,
            'dst_port': 22,
            'event_type': 'ssh_attempt',
            'message': 'Failed password for invalid user root from 203.0.113.10 port 54322 ssh2'
        },
        {
            'timestamp': '2024-01-15T10:25:33Z',
            'src_ip': '198.51.100.50',
            'dst_ip': '192.168.1.1',
            'src_port': 41234,
            'dst_port': 80,
            'event_type': 'port_scan',
            'message': 'SYN scan detected from 198.51.100.50 targeting multiple ports'
        },
        {
            'timestamp': '2024-01-15T10:26:45Z',
            'src_ip': '198.51.100.50',
            'dst_ip': '192.168.1.1',
            'src_port': 41235,
            'dst_port': 80,
            'event_type': 'http_request',
            'message': 'GET /admin/config.php HTTP/1.1 404 Not Found - fuzzing detected'
        },
        {
            'timestamp': '2024-01-15T10:27:01Z',
            'src_ip': '192.168.1.50',
            'dst_ip': '192.168.1.1',
            'src_port': 51234,
            'dst_port': 80,
            'event_type': 'http_request',
            'message': 'GET /index.html HTTP/1.1 200 OK'
        }
    ]

def main():
    """Point d'entrée principal"""
    print("""
╔══════════════════════════════════════════════════════════╗
║            SOC IA - MITRE ATT&CK + XAI                  ║
║         Ateliers A (Trust) + C (Anomaly) + D (MITRE)    ║
╚══════════════════════════════════════════════════════════╝
    """)
    
    # Initialisation
    pipeline = SOCPipeline()
    
    # Chargement des événements
    events = load_sample_events()
    print(f"\n📥 Chargement de {len(events)} événements de test\n")
    
    # Traitement
    results = pipeline.process_batch(events)
    
    # Résumé
    pipeline.generate_summary()
    
    # Sauvegarde
    pipeline.save_results()
    
    # Génération matrice MITRE
    print("\n🗺️ Génération matrice MITRE...")
    matrix = pipeline.mitre_mapper.create_mitre_matrix(events)
    if not matrix.empty:
        print(matrix.to_string(index=False))
        matrix.to_csv('outputs/mitre_matrix.csv', index=False)
        print("✅ Matrice sauvegardée: outputs/mitre_matrix.csv")
        
        # Export Navigator
        pipeline.mitre_mapper.export_to_navigator(matrix)
    
    print("\n✅ Pipeline terminé!")
    print("📁 Fichiers générés:")
    print("   - outputs/soc_results.json")
    print("   - outputs/mitre_matrix.csv")
    print("   - outputs/mitre_navigator.json")
    print("\n🌐 Pour visualiser la matrice MITRE:")
    print("   https://mitre-attack.github.io/attack-navigator/")

if __name__ == '__main__':
    main()