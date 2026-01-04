"""
Agent de calibration de confiance
Utilise Temperature Scaling pour améliorer la fiabilité des décisions
"""
import numpy as np
import json
from pathlib import Path
from typing import Dict, Tuple

class TrustAgent:
    def __init__(self, temperature: float = 1.5, threshold: float = 0.7):
        """
        Initialise l'agent de confiance
        
        Args:
            temperature: Facteur de scaling (>1 = moins confiant, <1 = plus confiant)
            threshold: Seuil de décision calibré
        """
        self.temperature = temperature
        self.threshold = threshold
        self.calibration_data = []
        self.max_calibration_samples = 100
        
    def calibrate_decision(self, 
                          llm_confidence: float, 
                          anomaly_score: float,
                          heuristic_score: float = 0.5) -> Tuple[float, Dict]:
        """
        Calibre la décision en fusionnant plusieurs sources de confiance
        
        Args:
            llm_confidence: Confiance du LLM (0-1)
            anomaly_score: Score d'anomalie (0-1, 1=anomalie)
            heuristic_score: Score heuristique optionnel (0-1)
            
        Returns:
            Tuple (calibrated_score, analysis)
        """
        # 1. Fusion des scores avec pondération
        weights = {
            'llm': 0.4,
            'anomaly': 0.4,
            'heuristic': 0.2
        }
        
        # Score composite brut
        raw_score = (
            weights['llm'] * llm_confidence +
            weights['anomaly'] * anomaly_score +
            weights['heuristic'] * heuristic_score
        )
        
        # 2. Application du Temperature Scaling
        calibrated_score = self._apply_temperature_scaling(raw_score)
        
        # 3. Décision binaire
        should_alert = calibrated_score >= self.threshold
        
        # 4. Calcul de la confiance dans la décision
        decision_confidence = abs(calibrated_score - self.threshold) / 0.5
        decision_confidence = np.clip(decision_confidence, 0, 1)
        
        analysis = {
            'raw_score': float(raw_score),
            'calibrated_score': float(calibrated_score),
            'should_alert': should_alert,
            'decision_confidence': float(decision_confidence),
            'sources': {
                'llm_confidence': float(llm_confidence),
                'anomaly_score': float(anomaly_score),
                'heuristic_score': float(heuristic_score)
            },
            'weights': weights,
            'temperature': self.temperature,
            'threshold': self.threshold
        }
        
        return calibrated_score, analysis
    
    def _apply_temperature_scaling(self, raw_score: float) -> float:
        """
        Applique le temperature scaling pour calibrer la confiance
        
        T > 1: Rend le modèle moins confiant (spread plus large)
        T < 1: Rend le modèle plus confiant (spread plus étroit)
        T = 1: Pas de changement
        """
        # Conversion en logits
        epsilon = 1e-10
        raw_score = np.clip(raw_score, epsilon, 1 - epsilon)
        logit = np.log(raw_score / (1 - raw_score))
        
        # Scaling avec température
        scaled_logit = logit / self.temperature
        
        # Retour en probabilité
        calibrated = 1 / (1 + np.exp(-scaled_logit))
        
        return float(np.clip(calibrated, 0, 1))
    
    def add_calibration_sample(self, 
                              prediction: float, 
                              ground_truth: bool,
                              event_data: Dict = None):
        """
        Ajoute un échantillon pour améliorer la calibration
        
        Args:
            prediction: Score prédit (calibré)
            ground_truth: Vrai label (True=malicious, False=normal)
            event_data: Données de l'événement (optionnel)
        """
        sample = {
            'prediction': float(prediction),
            'ground_truth': int(ground_truth),
            'timestamp': event_data.get('timestamp') if event_data else None
        }
        
        self.calibration_data.append(sample)
        
        # Limite la taille de l'historique
        if len(self.calibration_data) > self.max_calibration_samples:
            self.calibration_data = self.calibration_data[-self.max_calibration_samples:]
    
    def compute_calibration_metrics(self) -> Dict:
        """
        Calcule les métriques de calibration (Brier score, ECE)
        
        Returns:
            Dict avec métriques de calibration
        """
        if len(self.calibration_data) < 10:
            return {
                'error': 'Not enough calibration samples',
                'samples': len(self.calibration_data)
            }
        
        predictions = np.array([s['prediction'] for s in self.calibration_data])
        ground_truths = np.array([s['ground_truth'] for s in self.calibration_data])
        
        # Brier Score (MSE des probabilités)
        brier_score = np.mean((predictions - ground_truths) ** 2)
        
        # Expected Calibration Error (ECE)
        ece = self._compute_ece(predictions, ground_truths)
        
        # Accuracy
        binary_predictions = (predictions >= self.threshold).astype(int)
        accuracy = np.mean(binary_predictions == ground_truths)
        
        # Confusion matrix
        tp = np.sum((binary_predictions == 1) & (ground_truths == 1))
        fp = np.sum((binary_predictions == 1) & (ground_truths == 0))
        tn = np.sum((binary_predictions == 0) & (ground_truths == 0))
        fn = np.sum((binary_predictions == 0) & (ground_truths == 1))
        
        # Métriques dérivées
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        
        return {
            'brier_score': float(brier_score),
            'ece': float(ece),
            'accuracy': float(accuracy),
            'precision': float(precision),
            'recall': float(recall),
            'f1_score': float(f1),
            'confusion_matrix': {
                'tp': int(tp), 'fp': int(fp),
                'tn': int(tn), 'fn': int(fn)
            },
            'total_samples': len(self.calibration_data)
        }
    
    def _compute_ece(self, predictions: np.ndarray, ground_truths: np.ndarray, n_bins: int = 10) -> float:
        """
        Calcule l'Expected Calibration Error
        
        ECE mesure l'écart entre confiance prédite et précision réelle
        """
        bin_boundaries = np.linspace(0, 1, n_bins + 1)
        ece = 0
        
        for i in range(n_bins):
            bin_lower = bin_boundaries[i]
            bin_upper = bin_boundaries[i + 1]
            
            # Échantillons dans ce bin
            in_bin = (predictions >= bin_lower) & (predictions < bin_upper)
            
            if np.sum(in_bin) > 0:
                # Confiance moyenne dans le bin
                avg_confidence = np.mean(predictions[in_bin])
                
                # Précision réelle dans le bin
                avg_accuracy = np.mean(ground_truths[in_bin])
                
                # Proportion d'échantillons dans le bin
                bin_weight = np.sum(in_bin) / len(predictions)
                
                # Contribution au ECE
                ece += bin_weight * abs(avg_confidence - avg_accuracy)
        
        return ece
    
    def optimize_temperature(self) -> float:
        """
        Optimise la température pour minimiser le Brier Score
        (recherche par grille simple)
        """
        if len(self.calibration_data) < 20:
            print("⚠️ Pas assez d'échantillons pour optimiser")
            return self.temperature
        
        predictions = np.array([s['prediction'] for s in self.calibration_data])
        ground_truths = np.array([s['ground_truth'] for s in self.calibration_data])
        
        best_temp = self.temperature
        best_brier = float('inf')
        
        # Test différentes températures
        for temp in np.linspace(0.5, 3.0, 26):
            # Recalibre avec cette température
            temp_predictions = []
            for pred in predictions:
                epsilon = 1e-10
                pred = np.clip(pred, epsilon, 1 - epsilon)
                logit = np.log(pred / (1 - pred))
                scaled_logit = logit / temp
                calibrated = 1 / (1 + np.exp(-scaled_logit))
                temp_predictions.append(calibrated)
            
            temp_predictions = np.array(temp_predictions)
            brier = np.mean((temp_predictions - ground_truths) ** 2)
            
            if brier < best_brier:
                best_brier = brier
                best_temp = temp
        
        old_temp = self.temperature
        self.temperature = best_temp
        
        print(f"✅ Température optimisée: {old_temp:.2f} → {best_temp:.2f}")
        print(f"   Brier score: {best_brier:.4f}")
        
        return best_temp
    
    def save_calibration_data(self, filepath: str = 'data/calibration_data.json'):
        """Sauvegarde les données de calibration"""
        Path(filepath).parent.mkdir(exist_ok=True)
        
        data = {
            'temperature': self.temperature,
            'threshold': self.threshold,
            'samples': self.calibration_data
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"💾 Données de calibration sauvegardées: {filepath}")
    
    def load_calibration_data(self, filepath: str = 'data/calibration_data.json'):
        """Charge les données de calibration"""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            self.temperature = data.get('temperature', self.temperature)
            self.threshold = data.get('threshold', self.threshold)
            self.calibration_data = data.get('samples', [])
            
            print(f"✅ Données de calibration chargées: {len(self.calibration_data)} échantillons")
        except FileNotFoundError:
            print(f"⚠️ Fichier non trouvé: {filepath}")

if __name__ == '__main__':
    # Test
    agent = TrustAgent(temperature=1.5)
    
    print("🧪 Test de calibration")
    print(f"Température: {agent.temperature}")
    print(f"Seuil: {agent.threshold}\n")
    
    # Scénarios de test
    scenarios = [
        {'name': 'Attaque évidente', 'llm': 0.9, 'anomaly': 0.95, 'heuristic': 0.8},
        {'name': 'Normal évident', 'llm': 0.2, 'anomaly': 0.1, 'heuristic': 0.3},
        {'name': 'Cas ambigu', 'llm': 0.6, 'anomaly': 0.5, 'heuristic': 0.55},
    ]
    
    for scenario in scenarios:
        score, analysis = agent.calibrate_decision(
            scenario['llm'],
            scenario['anomaly'],
            scenario['heuristic']
        )
        
        print(f"📊 {scenario['name']}:")
        print(f"  Score brut: {analysis['raw_score']:.3f}")
        print(f"  Score calibré: {score:.3f}")
        print(f"  Alerte: {analysis['should_alert']}")
        print(f"  Confiance: {analysis['decision_confidence']:.3f}\n")