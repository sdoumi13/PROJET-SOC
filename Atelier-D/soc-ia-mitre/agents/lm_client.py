"""
Client LLM pour communication avec LM Studio
Compatible avec l'API OpenAI
"""
import requests
import json
from typing import Dict, Optional

class LMClient:
    def __init__(self, base_url: str = "http://192.168.11.1:1234/v1", timeout: int = 30):

        self.base_url = base_url
        self.timeout = timeout
        self.chat_endpoint = f"{base_url}/chat/completions"
        
    def query(self, 
              prompt: str, 
              system_prompt: Optional[str] = None,
              temperature: float = 0.3,
              max_tokens: int = 500) -> Dict:
        """
        Envoie une requête au LLM
        
        Args:
            prompt: Prompt utilisateur
            system_prompt: Prompt système optionnel
            temperature: Température (0.0-1.0)
            max_tokens: Nombre maximum de tokens
            
        Returns:
            Dict avec 'response', 'confidence', et 'raw'
        """
        messages = []
        
        if system_prompt:
            messages.append({
                "role": "user",
                "content": system_prompt
            })
        
        messages.append({
            "role": "user",
            "content": prompt
        })
        
        payload = {
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": False
        }
        
        try:
            response = requests.post(
                self.chat_endpoint,
                json=payload,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            data = response.json()
            
            # Extrait la réponse
            content = data['choices'][0]['message']['content']
            
            # Extrait la confiance si disponible (logprobs)
            confidence = self._extract_confidence(data)
            
            return {
                'response': content.strip(),
                'confidence': confidence,
                'raw': data
            }
            
        except requests.exceptions.RequestException as e:
            return {
                'response': f"Erreur LLM: {str(e)}",
                'confidence': 0.0,
                'error': str(e)
            }
    
    def _extract_confidence(self, response_data: Dict) -> float:
        """
        Extrait un score de confiance de la réponse LLM
        
        Note: LM Studio ne renvoie pas toujours les logprobs,
        donc on utilise une heuristique basée sur la longueur de réponse
        """
        try:
            # Si logprobs disponibles
            if 'logprobs' in response_data['choices'][0]:
                logprobs = response_data['choices'][0]['logprobs']
                if logprobs and 'token_logprobs' in logprobs:
                    # Moyenne des log probs
                    avg_logprob = sum(logprobs['token_logprobs']) / len(logprobs['token_logprobs'])
                    # Conversion en probabilité
                    import math
                    confidence = math.exp(avg_logprob)
                    return min(max(confidence, 0.0), 1.0)
            
            # Heuristique par défaut
            content = response_data['choices'][0]['message']['content']
            
            # Plus la réponse est longue et structurée, plus on est confiant
            length_score = min(len(content) / 200, 1.0)
            
            # Détecte les mots de certitude
            certainty_words = ['certainement', 'clairement', 'évidemment', 
                             'definitely', 'clearly', 'obviously']
            uncertainty_words = ['peut-être', 'possiblement', 'probablement',
                               'maybe', 'possibly', 'probably']
            
            content_lower = content.lower()
            certainty_boost = 0.1 if any(word in content_lower for word in certainty_words) else 0
            uncertainty_penalty = 0.15 if any(word in content_lower for word in uncertainty_words) else 0
            
            confidence = 0.6 + (length_score * 0.3) + certainty_boost - uncertainty_penalty
            
            return min(max(confidence, 0.0), 1.0)
            
        except Exception:
            return 0.5  # Confiance par défaut
    
    def analyze_security_event(self, event: Dict) -> Dict:
        """
        Analyse spécifique pour événements de sécurité
        """
        system_prompt = """Tu es un expert en cybersécurité travaillant dans un SOC.
Analyse les événements de sécurité et détermine s'ils sont malveillants.
Réponds de manière concise et factuelle.
Format: [MALVEILLANT/NORMAL] suivi d'une brève justification."""

        prompt = f"""Analyse cet événement:
        
Timestamp: {event.get('timestamp', 'N/A')}
Source IP: {event.get('src_ip', 'N/A')}
Type: {event.get('event_type', 'N/A')}
Message: {event.get('message', 'N/A')}

Est-ce malveillant?"""

        result = self.query(prompt, system_prompt=system_prompt, temperature=0.3)
        
        # Parse la réponse
        response_text = result['response'].upper()
        is_malicious = 'MALVEILLANT' in response_text or 'MALICIOUS' in response_text
        
        return {
            'is_malicious': is_malicious,
            'confidence': result['confidence'],
            'explanation': result['response'],
            'raw': result.get('raw')
        }
    
    def test_connection(self) -> bool:
        """Teste la connexion à LM Studio"""
        try:
            response = self.query("Test", max_tokens=10)
            return 'error' not in response
        except Exception:
            return False

if __name__ == '__main__':
    # Test
    client = LMClient()
    
    print("🧪 Test de connexion LM Studio...")
    if client.test_connection():
        print("✅ Connexion OK")
        
        # Test d'analyse
        test_event = {
            'timestamp': '2024-01-15 10:23:45',
            'src_ip': '192.168.1.100',
            'event_type': 'ssh_attempt',
            'message': 'Failed password for invalid user admin from 192.168.1.100 port 54321'
        }
        
        print("\n🔍 Test d'analyse...")
        result = client.analyze_security_event(test_event)
        print(f"Malveillant: {result['is_malicious']}")
        print(f"Confiance: {result['confidence']:.2f}")
        print(f"Explication: {result['explanation']}")
    else:
        print("❌ Échec de connexion")
        print("Vérifiez que LM Studio est lancé sur http://localhost:1234")