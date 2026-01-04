"""
Test du SOC IA avec événements réalistes
Charge data/test_events.json et évalue les performances
"""
import json
import sys
from pathlib import Path
from datetime import datetime
import numpy as np

# Import des agents
sys.path.append('agents')
from lm_client import LMClient
from anomaly_detector import AnomalyDetector
from trust_agent import TrustAgent
from mitre_mapper import MitreMapper
from xai_explainer import XAIExplainer

class RealisticTester:
    def __init__(self):
        """Initialise le testeur avec événements réalistes"""
        print("🧪 Initialisation du testeur...")
        
        # Chargement des agents
        self.lm_client = LMClient()
        self.anomaly_detector = AnomalyDetector()
        self.trust_agent = TrustAgent(temperature=1.5, threshold=0.7)
        self.mitre_mapper = MitreMapper()
        self.xai_explainer = XAIExplainer(self.lm_client)
        
        # Métriques
        self.results = []
        self.confusion_matrix = {
            'tp': 0,  # True Positive
            'fp': 0,  # False Positive
            'tn': 0,  # True Negative
            'fn': 0   # False Negative
        }
        
    def load_events(self, filepath='data/test_events.json'):
        """Charge les événements de test"""
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        print(f"✅ {len(data['events'])} événements chargés")
        print(f"   Malveillants: {data['attack_statistics']['malicious_events']}")
        print(f"   Normaux: {data['attack_statistics']['normal_events']}")
        
        return data['events']
    
    def test_event(self, event):
        """Teste un événement à travers le pipeline"""
        # Ground truth
        is_malicious_truth = (event.get('expected') == 'malicious')
        
        # Pipeline
        # 1. Détection anomalie
        anomaly_score, _ = self.anomaly_detector.detect(event)
        
        # 2. Analyse LLM
        llm_analysis = self.lm_client.analyze_security_event(event)
        
        # 3. Calibration
        heuristic = self._compute_heuristic(event)
        trust_score, trust_analysis = self.trust_agent.calibrate_decision(
            llm_analysis['confidence'],
            anomaly_score,
            heuristic
        )
        
        # 4. MITRE
        mitre_techniques = self.mitre_mapper.map_event(event)
        
        # 5. XAI
        explanation = self.xai_explainer.explain(
            event, mitre_techniques, anomaly_score, trust_score, llm_analysis
        )
        
        # Prédiction
        is_malicious_pred = trust_analysis['should_alert']
        
        # Mise à jour confusion matrix
        if is_malicious_truth and is_malicious_pred:
            self.confusion_matrix['tp'] += 1
            result_type = 'TP'
        elif not is_malicious_truth and is_malicious_pred:
            self.confusion_matrix['fp'] += 1
            result_type = 'FP'
        elif not is_malicious_truth and not is_malicious_pred:
            self.confusion_matrix['tn'] += 1
            result_type = 'TN'
        else:  # is_malicious_truth and not is_malicious_pred
            self.confusion_matrix['fn'] += 1
            result_type = 'FN'
        
        result = {
            'event_id': event['id'],
            'expected': event['expected'],
            'predicted': 'malicious' if is_malicious_pred else 'normal',
            'result_type': result_type,
            'scores': {
                'anomaly': anomaly_score,
                'llm_confidence': llm_analysis['confidence'],
                'trust': trust_score,
                'threat_level': explanation['scores']['threat_level']
            },
            'mitre_techniques': [t['technique_id'] for t in mitre_techniques],
            'attack_type': event.get('attack_type', 'none')
        }
        
        self.results.append(result)
        
        return result, result_type
    
    def _compute_heuristic(self, event):
        """Heuristique simple"""
        message = event.get('message', '').lower()
        bad_keywords = ['failed', 'denied', 'invalid', 'error', 'attack', 
                       'exploit', 'scan', 'unauthorized', 'forbidden', 'traversal']
        good_keywords = ['success', 'ok', 'accepted', 'authorized']
        
        bad = sum(1 for kw in bad_keywords if kw in message)
        good = sum(1 for kw in good_keywords if kw in message)
        
        if bad > good:
            return 0.5 + min(bad, 5) / 10
        else:
            return 0.5 - min(good, 5) / 10
    
    def run_all_tests(self, events):
        """Exécute tous les tests"""
        print(f"\n{'='*70}")
        print("🚀 DÉBUT DES TESTS")
        print(f"{'='*70}\n")
        
        for i, event in enumerate(events, 1):
            print(f"\n[{i}/{len(events)}] Test événement: {event['id']}")
            print(f"   Type: {event.get('attack_type', 'none')}")
            print(f"   Attendu: {event['expected']}")
            
            result, result_type = self.test_event(event)
            
            # Affichage résultat
            color = '🟢' if result_type in ['TP', 'TN'] else '🔴'
            print(f"   {color} Résultat: {result_type}")
            print(f"   Prédit: {result['predicted']}")
            print(f"   Trust score: {result['scores']['trust']:.3f}")
            print(f"   Niveau menace: {result['scores']['threat_level']}")
            
            if result['mitre_techniques']:
                print(f"   Techniques MITRE: {', '.join(result['mitre_techniques'][:3])}")
        
        print(f"\n{'='*70}")
        print("✅ TESTS TERMINÉS")
        print(f"{'='*70}\n")
    
    def print_metrics(self):
        """Affiche les métriques de performance"""
        cm = self.confusion_matrix
        
        # Calculs
        total = cm['tp'] + cm['fp'] + cm['tn'] + cm['fn']
        accuracy = (cm['tp'] + cm['tn']) / total if total > 0 else 0
        precision = cm['tp'] / (cm['tp'] + cm['fp']) if (cm['tp'] + cm['fp']) > 0 else 0
        recall = cm['tp'] / (cm['tp'] + cm['fn']) if (cm['tp'] + cm['fn']) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        
        # Taux d'erreur
        fpr = cm['fp'] / (cm['fp'] + cm['tn']) if (cm['fp'] + cm['tn']) > 0 else 0
        fnr = cm['fn'] / (cm['fn'] + cm['tp']) if (cm['fn'] + cm['tp']) > 0 else 0
        
        print("\n" + "="*70)
        print("📊 MÉTRIQUES DE PERFORMANCE")
        print("="*70)
        
        print("\n🎯 Matrice de Confusion:")
        print(f"""
                    Prédit Négatif  |  Prédit Positif
    ─────────────────────────────────────────────────
    Réel Négatif  |      {cm['tn']:3d}       |      {cm['fp']:3d}      
    Réel Positif  |      {cm['fn']:3d}       |      {cm['tp']:3d}      
        """)
        
        print("📈 Métriques Globales:")
        print(f"   Accuracy (Précision globale)  : {accuracy:.2%}")
        print(f"   Precision (Précision positive): {precision:.2%}")
        print(f"   Recall (Sensibilité/TPR)      : {recall:.2%}")
        print(f"   F1-Score                       : {f1:.2%}")
        print(f"   False Positive Rate (FPR)     : {fpr:.2%}")
        print(f"   False Negative Rate (FNR)     : {fnr:.2%}")
        
        print("\n📋 Détails:")
        print(f"   True Positives  (TP): {cm['tp']:3d} - Attaques correctement détectées")
        print(f"   True Negatives  (TN): {cm['tn']:3d} - Trafic normal correctement ignoré")
        print(f"   False Positives (FP): {cm['fp']:3d} - Fausses alertes")
        print(f"   False Negatives (FN): {cm['fn']:3d} - Attaques manquées")
        
        print(f"\n   Total événements: {total}")
        
        # Analyse par type d'attaque
        print("\n🎨 Performance par type d'attaque:")
        attack_types = {}
        for result in self.results:
            attack_type = result['attack_type']
            if attack_type not in attack_types:
                attack_types[attack_type] = {'correct': 0, 'total': 0}
            
            attack_types[attack_type]['total'] += 1
            if result['result_type'] in ['TP', 'TN']:
                attack_types[attack_type]['correct'] += 1
        
        for attack_type, stats in sorted(attack_types.items()):
            accuracy = stats['correct'] / stats['total'] if stats['total'] > 0 else 0
            print(f"   {attack_type:20s}: {accuracy:6.1%} ({stats['correct']}/{stats['total']})")
        
        print("="*70 + "\n")
    
    def save_results(self, filepath='outputs/test_results.json'):
        """Sauvegarde les résultats"""
        output = {
            'timestamp': datetime.now().isoformat(),
            'confusion_matrix': self.confusion_matrix,
            'metrics': self._calculate_metrics(),
            'results': self.results
        }
        
        Path(filepath).parent.mkdir(exist_ok=True)
        with open(filepath, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"💾 Résultats sauvegardés: {filepath}")
    
    def _calculate_metrics(self):
        """Calcule toutes les métriques"""
        cm = self.confusion_matrix
        total = cm['tp'] + cm['fp'] + cm['tn'] + cm['fn']
        
        accuracy = (cm['tp'] + cm['tn']) / total if total > 0 else 0
        precision = cm['tp'] / (cm['tp'] + cm['fp']) if (cm['tp'] + cm['fp']) > 0 else 0
        recall = cm['tp'] / (cm['tp'] + cm['fn']) if (cm['tp'] + cm['fn']) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        fpr = cm['fp'] / (cm['fp'] + cm['tn']) if (cm['fp'] + cm['tn']) > 0 else 0
        fnr = cm['fn'] / (cm['fn'] + cm['tp']) if (cm['fn'] + cm['tp']) > 0 else 0
        
        return {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'false_positive_rate': fpr,
            'false_negative_rate': fnr
        }

def main():
    """Point d'entrée"""
    print("""
╔══════════════════════════════════════════════════════════╗
║       TEST SOC IA AVEC ÉVÉNEMENTS RÉALISTES             ║
╚══════════════════════════════════════════════════════════╝
    """)
    
    # Initialisation
    tester = RealisticTester()
    
    # Chargement événements
    try:
        events = tester.load_events('data/test_events.json')
    except FileNotFoundError:
        print("❌ Fichier data/test_events.json non trouvé")
        print("Veuillez créer ce fichier avec les événements de test")
        return
    
    # Exécution des tests
    tester.run_all_tests(events)
    
    # Affichage des métriques
    tester.print_metrics()
    
    # Sauvegarde
    tester.save_results()
    
    print("\n✅ Test terminé!")
    print("📊 Consultez outputs/test_results.json pour les détails")

if __name__ == '__main__':
    main()