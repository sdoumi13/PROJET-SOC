"""
Détecteur d'anomalies utilisant Isolation Forest
"""
import joblib
import numpy as np
from pathlib import Path
from typing import Dict, Tuple
from features import FeatureExtractor

class AnomalyDetector:
    def __init__(self, model_path: str = 'data/anomaly_model.pkl'):
        """
        Initialise le détecteur d'anomalies
        
        Args:
            model_path: Chemin vers le modèle Isolation Forest entraîné
        """
        self.model_path = Path(model_path)
        self.model = None
        self.feature_extractor = FeatureExtractor()
        self.threshold = 0.7  # Seuil de décision
        
        self._load_model()
    
    def _load_model(self):
        """Charge le modèle pré-entraîné"""
        if self.model_path.exists():
            try:
                self.model = joblib.load(self.model_path)
                print(f"✅ Modèle chargé depuis {self.model_path}")
            except Exception as e:
                print(f"⚠️ Erreur chargement modèle: {e}")
                print("Le détecteur utilisera un modèle par défaut")
                self._create_default_model()
        else:
            print("⚠️ Modèle non trouvé, création d'un modèle par défaut")
            self._create_default_model()
    
    def _create_default_model(self):
        """Crée un modèle Isolation Forest par défaut"""
        from sklearn.ensemble import IsolationForest
        
        self.model = IsolationForest(
            contamination=0.1,  # 10% d'anomalies attendues
            random_state=42,
            n_estimators=100
        )
        
        # Entraîne sur des données factices pour initialiser
        dummy_data = np.random.randn(100, 22)  # 22 features
        self.model.fit(dummy_data)
    
    def detect(self, event: Dict) -> Tuple[float, Dict]:
        """
        Détecte si un événement est une anomalie
        
        Args:
            event: Événement à analyser
            
        Returns:
            Tuple (anomaly_score, analysis_result)
            - anomaly_score: Score entre 0 (normal) et 1 (anomalie)
            - analysis_result: Dict avec détails de l'analyse
        """
        # Extraction des features
        features = self.feature_extractor.extract(event)
        feature_vector = self.feature_extractor.get_feature_vector(features)
        
        # Reshape pour sklearn
        X = feature_vector.reshape(1, -1)
        
        # Prédiction
        # -1 = anomalie, 1 = normal
        prediction = self.model.predict(X)[0]
        
        # Score d'anomalie (plus négatif = plus anormal)
        # decision_function retourne des valeurs négatives pour les anomalies
        raw_score = self.model.decision_function(X)[0]
        
        # Normalisation du score entre 0 et 1
        # Les scores typiques sont entre -0.5 et 0.5
        anomaly_score = self._normalize_score(raw_score)
        
        # Décision binaire
        is_anomaly = anomaly_score >= self.threshold
        
        # Analyse détaillée
        analysis = {
            'is_anomaly': is_anomaly,
            'anomaly_score': float(anomaly_score),
            'raw_score': float(raw_score),
            'prediction': 'ANOMALY' if prediction == -1 else 'NORMAL',
            'confidence': abs(anomaly_score - 0.5) * 2,  # Distance au seuil
            'features': features,
            'top_suspicious_features': self._identify_suspicious_features(features)
        }
        
        return anomaly_score, analysis
    
    def _normalize_score(self, raw_score: float) -> float:
        """
        Normalise le score d'anomalie entre 0 et 1
        
        Isolation Forest donne des scores négatifs pour anomalies,
        positifs pour normal. On inverse et normalise.
        """
        # Typiquement les scores sont entre -0.5 et 0.5
        # On applique une sigmoïde inversée
        normalized = 1 / (1 + np.exp(raw_score * 4))
        return float(np.clip(normalized, 0, 1))
    
    def _identify_suspicious_features(self, features: Dict) -> list:
        """Identifie les features les plus suspectes"""
        suspicious = []
        
        # Règles heuristiques pour identifier ce qui est suspect
        if features.get('same_ip_frequency', 0) > 5:
            suspicious.append(('same_ip_frequency', features['same_ip_frequency']))
        
        if features.get('suspicious_keyword_count', 0) > 2:
            suspicious.append(('suspicious_keyword_count', features['suspicious_keyword_count']))
        
        if features.get('is_repeated_failure', 0) == 1:
            suspicious.append(('repeated_failures', 'Detected'))
        
        if features.get('is_rapid_succession', 0) == 1:
            suspicious.append(('rapid_succession', 'Detected'))
        
        if features.get('time_since_last_similar', 9999) < 5:
            suspicious.append(('rapid_repeat', f"{features['time_since_last_similar']:.1f}s"))
        
        if features.get('is_night', 0) == 1:
            suspicious.append(('night_activity', 'After hours'))
        
        return suspicious
    
    def batch_detect(self, events: list) -> list:
        """Détecte anomalies sur un batch d'événements"""
        results = []
        
        for event in events:
            score, analysis = self.detect(event)
            results.append({
                'event': event,
                'score': score,
                'analysis': analysis
            })
        
        return results
    
    def update_threshold(self, new_threshold: float):
        """Met à jour le seuil de décision"""
        self.threshold = np.clip(new_threshold, 0, 1)
        print(f"Seuil mis à jour: {self.threshold}")
    
    def get_statistics(self, events: list) -> Dict:
        """Calcule des statistiques sur un ensemble d'événements"""
        results = self.batch_detect(events)
        
        anomaly_scores = [r['score'] for r in results]
        anomalies = [r for r in results if r['analysis']['is_anomaly']]
        
        return {
            'total_events': len(events),
            'anomalies_detected': len(anomalies),
            'anomaly_rate': len(anomalies) / max(len(events), 1),
            'mean_score': np.mean(anomaly_scores),
            'std_score': np.std(anomaly_scores),
            'max_score': np.max(anomaly_scores),
            'min_score': np.min(anomaly_scores)
        }

if __name__ == '__main__':
    # Test
    detector = AnomalyDetector()
    
    # Test avec événement normal
    normal_event = {
        'timestamp': '2024-01-15T14:23:45Z',
        'src_ip': '192.168.1.50',
        'dst_ip': '10.0.0.1',
        'src_port': 51234,
        'dst_port': 80,
        'event_type': 'http_request',
        'message': 'GET /index.html HTTP/1.1 200 OK'
    }
    
    # Test avec événement suspect
    suspicious_event = {
        'timestamp': '2024-01-15T02:23:45Z',
        'src_ip': '203.0.113.10',
        'dst_ip': '10.0.0.1',
        'src_port': 54321,
        'dst_port': 22,
        'event_type': 'ssh_attempt',
        'message': 'Failed password for invalid user admin from 203.0.113.10 port 54321 ssh2'
    }
    
    print("🧪 Test événement NORMAL:")
    score, analysis = detector.detect(normal_event)
    print(f"  Score: {score:.3f}")
    print(f"  Anomalie: {analysis['is_anomaly']}")
    print(f"  Features suspectes: {analysis['top_suspicious_features']}")
    
    print("\n🧪 Test événement SUSPECT:")
    score, analysis = detector.detect(suspicious_event)
    print(f"  Score: {score:.3f}")
    print(f"  Anomalie: {analysis['is_anomaly']}")
    print(f"  Features suspectes: {analysis['top_suspicious_features']}")