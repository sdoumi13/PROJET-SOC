"""
Extraction de features pour la détection d'anomalies
"""
import re
from datetime import datetime
from typing import Dict, List
import numpy as np

class FeatureExtractor:
    def __init__(self):
        self.event_history = []  # Historique pour calculer fréquences
        self.max_history = 1000
        
    def extract(self, event: Dict) -> Dict:
        """
        Extrait les features d'un événement pour ML
        
        Returns:
            Dict avec features numériques et catégorielles
        """
        features = {}
        
        # 1. Features temporelles
        features.update(self._extract_temporal_features(event))
        
        # 2. Features réseau
        features.update(self._extract_network_features(event))
        
        # 3. Features de fréquence
        features.update(self._extract_frequency_features(event))
        
        # 4. Features de contenu
        features.update(self._extract_content_features(event))
        
        # 5. Features comportementales
        features.update(self._extract_behavioral_features(event))
        
        # Mise à jour de l'historique
        self._update_history(event)
        
        return features
    
    def _extract_temporal_features(self, event: Dict) -> Dict:
        """Features liées au temps"""
        features = {}
        
        try:
            timestamp = event.get('timestamp')
            if isinstance(timestamp, str):
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            else:
                dt = datetime.now()
            
            features['hour'] = dt.hour
            features['day_of_week'] = dt.weekday()
            features['is_weekend'] = 1 if dt.weekday() >= 5 else 0
            features['is_night'] = 1 if dt.hour < 6 or dt.hour > 22 else 0
            
        except Exception:
            features['hour'] = 0
            features['day_of_week'] = 0
            features['is_weekend'] = 0
            features['is_night'] = 0
        
        return features
    
    def _extract_network_features(self, event: Dict) -> Dict:
        """Features réseau"""
        features = {}
        
        src_ip = event.get('src_ip', '')
        dst_ip = event.get('dst_ip', '')
        
        # IP privée vs publique
        features['src_is_private'] = 1 if self._is_private_ip(src_ip) else 0
        features['dst_is_private'] = 1 if self._is_private_ip(dst_ip) else 0
        
        # Ports
        src_port = event.get('src_port', 0)
        dst_port = event.get('dst_port', 0)
        
        features['src_port'] = int(src_port) if src_port else 0
        features['dst_port'] = int(dst_port) if dst_port else 0
        features['is_common_port'] = 1 if dst_port in [22, 80, 443, 3389, 21, 23] else 0
        
        return features
    
    def _extract_frequency_features(self, event: Dict) -> Dict:
        """Features de fréquence"""
        features = {}
        
        src_ip = event.get('src_ip', '')
        event_type = event.get('event_type', '')
        
        # Compte les événements similaires dans l'historique
        recent_events = self.event_history[-100:]  # 100 derniers
        
        # Fréquence de la même IP
        same_ip_count = sum(1 for e in recent_events if e.get('src_ip') == src_ip)
        features['same_ip_frequency'] = same_ip_count
        
        # Fréquence du même type
        same_type_count = sum(1 for e in recent_events if e.get('event_type') == event_type)
        features['same_type_frequency'] = same_type_count
        
        # Temps depuis dernier événement similaire
        features['time_since_last_similar'] = self._time_since_last_similar(event)
        
        return features
    
    def _extract_content_features(self, event: Dict) -> Dict:
        """Features du contenu du message"""
        features = {}
        
        message = event.get('message', '').lower()
        
        # Mots-clés suspects
        suspicious_keywords = [
            'failed', 'invalid', 'denied', 'error', 'attack',
            'scan', 'exploit', 'brute', 'unauthorized', 'forbidden'
        ]
        
        features['suspicious_keyword_count'] = sum(
            1 for keyword in suspicious_keywords if keyword in message
        )
        
        # Longueur du message
        features['message_length'] = len(message)
        
        # Caractères spéciaux
        features['special_char_ratio'] = sum(
            1 for c in message if not c.isalnum() and not c.isspace()
        ) / max(len(message), 1)
        
        # Patterns
        features['has_ip_pattern'] = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', message) else 0
        features['has_url_pattern'] = 1 if re.search(r'https?://', message) else 0
        
        # Code HTTP si présent
        http_code_match = re.search(r'\b([1-5]\d{2})\b', message)
        features['http_code'] = int(http_code_match.group(1)) if http_code_match else 0
        features['is_http_error'] = 1 if features['http_code'] >= 400 else 0
        
        return features
    
    def _extract_behavioral_features(self, event: Dict) -> Dict:
        """Features comportementales"""
        features = {}
        
        event_type = event.get('event_type', '')
        
        # Type d'événement encodé
        type_mapping = {
            'ssh_attempt': 1,
            'http_request': 2,
            'port_scan': 3,
            'dns_query': 4,
            'file_access': 5,
            'login_success': 6,
            'login_failure': 7
        }
        features['event_type_encoded'] = type_mapping.get(event_type, 0)
        
        # Séquence d'événements (pattern)
        features['is_repeated_failure'] = self._is_repeated_failure(event)
        features['is_rapid_succession'] = self._is_rapid_succession(event)
        
        return features
    
    def _is_private_ip(self, ip: str) -> bool:
        """Vérifie si une IP est privée"""
        if not ip:
            return False
        try:
            parts = [int(p) for p in ip.split('.')]
            return (
                parts[0] == 10 or
                (parts[0] == 172 and 16 <= parts[1] <= 31) or
                (parts[0] == 192 and parts[1] == 168)
            )
        except Exception:
            return False
    
    def _time_since_last_similar(self, event: Dict) -> float:
        """Temps écoulé depuis un événement similaire (en secondes)"""
        src_ip = event.get('src_ip', '')
        event_type = event.get('event_type', '')
        
        try:
            current_time = datetime.fromisoformat(
                event.get('timestamp', datetime.now().isoformat()).replace('Z', '+00:00')
            )
        except Exception:
            return 9999.0
        
        for past_event in reversed(self.event_history):
            if (past_event.get('src_ip') == src_ip and 
                past_event.get('event_type') == event_type):
                try:
                    past_time = datetime.fromisoformat(
                        past_event.get('timestamp', '').replace('Z', '+00:00')
                    )
                    delta = (current_time - past_time).total_seconds()
                    return max(delta, 0.1)
                except Exception:
                    pass
        
        return 9999.0  # Aucun événement similaire trouvé
    
    def _is_repeated_failure(self, event: Dict) -> int:
        """Détecte échecs répétés"""
        message = event.get('message', '').lower()
        src_ip = event.get('src_ip', '')
        
        if 'failed' not in message and 'denied' not in message:
            return 0
        
        # Compte les échecs récents de la même IP
        recent = self.event_history[-20:]
        failure_count = sum(
            1 for e in recent
            if e.get('src_ip') == src_ip and
            ('failed' in e.get('message', '').lower() or 'denied' in e.get('message', '').lower())
        )
        
        return 1 if failure_count >= 3 else 0
    
    def _is_rapid_succession(self, event: Dict) -> int:
        """Détecte événements en succession rapide"""
        src_ip = event.get('src_ip', '')
        
        recent = self.event_history[-10:]
        same_ip_recent = [e for e in recent if e.get('src_ip') == src_ip]
        
        return 1 if len(same_ip_recent) >= 5 else 0
    
    def _update_history(self, event: Dict):
        """Met à jour l'historique"""
        self.event_history.append(event)
        if len(self.event_history) > self.max_history:
            self.event_history = self.event_history[-self.max_history:]
    
    def get_feature_vector(self, features: Dict) -> np.ndarray:
        """Convertit features dict en vecteur numpy"""
        # Liste ordonnée des features pour le modèle
        feature_names = [
            'hour', 'day_of_week', 'is_weekend', 'is_night',
            'src_is_private', 'dst_is_private', 'src_port', 'dst_port', 'is_common_port',
            'same_ip_frequency', 'same_type_frequency', 'time_since_last_similar',
            'suspicious_keyword_count', 'message_length', 'special_char_ratio',
            'has_ip_pattern', 'has_url_pattern', 'http_code', 'is_http_error',
            'event_type_encoded', 'is_repeated_failure', 'is_rapid_succession'
        ]
        
        vector = np.array([features.get(name, 0) for name in feature_names])
        return vector

if __name__ == '__main__':
    # Test
    extractor = FeatureExtractor()
    
    test_event = {
        'timestamp': '2024-01-15T10:23:45Z',
        'src_ip': '192.168.1.100',
        'dst_ip': '10.0.0.1',
        'src_port': 54321,
        'dst_port': 22,
        'event_type': 'ssh_attempt',
        'message': 'Failed password for invalid user admin from 192.168.1.100'
    }
    
    features = extractor.extract(test_event)
    
    print("📊 Features extraites:")
    for key, value in features.items():
        print(f"  {key}: {value}")
    
    vector = extractor.get_feature_vector(features)
    print(f"\n🔢 Vecteur numpy shape: {vector.shape}")
    print(f"Valeurs: {vector}")