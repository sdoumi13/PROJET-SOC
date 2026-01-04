"""
XAI Explainer - Explications des décisions IA
Utilise le LLM pour générer des explications en langage naturel
"""
from typing import Dict, List
from lm_client import LMClient
import json

class XAIExplainer:
    def __init__(self, lm_client: LMClient = None):
        """
        Initialise l'explainer XAI
        
        Args:
            lm_client: Client LLM (si None, en crée un nouveau)
        """
        self.lm_client = lm_client if lm_client else LMClient()
        self.explanation_cache = {}
        
    def explain(self, 
                event: Dict,
                mitre_techniques: List[Dict],
                anomaly_score: float,
                trust_score: float,
                llm_analysis: Dict = None) -> Dict:
        """
        Génère une explication complète pour une décision
        
        Args:
            event: Événement analysé
            mitre_techniques: Techniques MITRE détectées
            anomaly_score: Score d'anomalie (0-1)
            trust_score: Score de confiance calibré (0-1)
            llm_analysis: Analyse LLM optionnelle
            
        Returns:
            Dict avec explication structurée
        """
        # Construction du contexte pour le LLM
        context = self._build_context(event, mitre_techniques, anomaly_score, trust_score, llm_analysis)
        
        # Génère l'explication via LLM
        explanation_text = self._generate_llm_explanation(context)
        
        # Analyse les composants de la décision
        decision_factors = self._analyze_decision_factors(
            anomaly_score, trust_score, mitre_techniques
        )
        
        # Recommandations d'action
        recommendations = self._generate_recommendations(
            trust_score, mitre_techniques, event
        )
        
        explanation = {
            'event_id': event.get('id', 'unknown'),
            'timestamp': event.get('timestamp'),
            'summary': self._generate_summary(trust_score, mitre_techniques),
            'explanation': explanation_text,
            'decision_factors': decision_factors,
            'mitre_mapping': {
                'techniques': [
                    {
                        'id': t['technique_id'],
                        'name': t['technique_name'],
                        'tactic': t['tactic'],
                        'confidence': t['confidence']
                    }
                    for t in mitre_techniques
                ],
                'kill_chain': self._extract_kill_chain(mitre_techniques)
            },
            'scores': {
                'anomaly_score': float(anomaly_score),
                'trust_score': float(trust_score),
                'threat_level': self._calculate_threat_level(trust_score, anomaly_score)
            },
            'recommendations': recommendations,
            'attribution': {
                'source_ip': event.get('src_ip'),
                'event_type': event.get('event_type'),
                'indicators': self._extract_indicators(event, mitre_techniques)
            }
        }
        
        return explanation
    
    def _build_context(self, event: Dict, techniques: List[Dict], 
                       anomaly_score: float, trust_score: float,
                       llm_analysis: Dict) -> str:
        """Construit le contexte pour le prompt LLM"""
        
        # Techniques MITRE formatées
        techniques_str = ""
        if techniques:
            techniques_str = "\n".join([
                f"  - {t['technique_id']} ({t['technique_name']}): "
                f"{t['tactic']} - Confiance {t['confidence']*100:.0f}%"
                for t in techniques[:3]  # Top 3
            ])
        else:
            techniques_str = "  Aucune technique spécifique détectée"
        
        # Analyse LLM si disponible
        llm_str = ""
        if llm_analysis:
            llm_str = f"\nAnalyse IA: {llm_analysis.get('explanation', 'N/A')}"
        
        context = f"""ÉVÉNEMENT DE SÉCURITÉ:
IP Source: {event.get('src_ip', 'N/A')}
Type: {event.get('event_type', 'N/A')}
Message: {event.get('message', 'N/A')[:200]}
Timestamp: {event.get('timestamp', 'N/A')}

SCORES D'ANALYSE:
- Score d'anomalie: {anomaly_score:.2f} (0=normal, 1=anomalie)
- Score de confiance calibré: {trust_score:.2f} (0=bénin, 1=malveillant)
- Niveau de menace: {self._calculate_threat_level(trust_score, anomaly_score)}

TECHNIQUES MITRE ATT&CK DÉTECTÉES:
{techniques_str}
{llm_str}
"""
        return context
    
    def _generate_llm_explanation(self, context: str) -> str:
        """Génère l'explication via le LLM"""
        
        system_prompt = """Tu es un expert en cybersécurité travaillant dans un SOC.
Ton rôle est d'expliquer les décisions de sécurité de manière claire et pédagogique.

Fournis une explication en 3-4 phrases qui couvre:
1. Ce qui a été détecté et pourquoi c'est préoccupant (ou non)
2. Comment les différents systèmes (anomalie ML, MITRE mapping) ont contribué à la décision
3. Le niveau de risque et la confiance dans l'évaluation
4. L'action recommandée

Sois précis, factuel et concis. Évite le jargon excessif."""

        prompt = f"""{context}

Explique cette analyse de sécurité de manière claire et professionnelle:"""

        try:
            result = self.lm_client.query(
                prompt,
                system_prompt=system_prompt,
                temperature=0.4,
                max_tokens=300
            )
            
            return result['response']
        
        except Exception as e:
            return f"Explication automatique non disponible: {str(e)}"
    
    def _generate_summary(self, trust_score: float, techniques: List[Dict]) -> str:
        """Génère un résumé court"""
        threat_level = self._calculate_threat_level(trust_score, 0)
        
        if not techniques:
            return f"Activité de niveau {threat_level} - Aucune technique MITRE identifiée"
        
        top_technique = techniques[0]
        
        return (f"Niveau {threat_level}: {top_technique['technique_name']} "
                f"({top_technique['technique_id']}) détecté avec "
                f"{len(techniques)} technique(s) associée(s)")
    
    def _analyze_decision_factors(self, anomaly_score: float, 
                                  trust_score: float,
                                  techniques: List[Dict]) -> Dict:
        """Analyse les facteurs ayant contribué à la décision"""
        
        factors = {
            'primary_indicators': [],
            'supporting_evidence': [],
            'confidence_level': 'High' if trust_score > 0.8 else 'Medium' if trust_score > 0.5 else 'Low'
        }
        
        # Analyse score d'anomalie
        if anomaly_score > 0.7:
            factors['primary_indicators'].append({
                'type': 'Anomalie comportementale',
                'description': f"Comportement hautement anormal détecté (score: {anomaly_score:.2f})",
                'weight': 'high'
            })
        elif anomaly_score > 0.4:
            factors['supporting_evidence'].append({
                'type': 'Anomalie modérée',
                'description': f"Comportement inhabituel observé (score: {anomaly_score:.2f})",
                'weight': 'medium'
            })
        
        # Analyse techniques MITRE
        if techniques:
            high_conf_techniques = [t for t in techniques if t['confidence'] > 0.7]
            
            if high_conf_techniques:
                factors['primary_indicators'].append({
                    'type': 'Techniques MITRE',
                    'description': f"{len(high_conf_techniques)} technique(s) MITRE à haute confiance",
                    'weight': 'high',
                    'details': [f"{t['technique_id']}: {t['technique_name']}" 
                               for t in high_conf_techniques[:3]]
                })
        
        # Analyse score de confiance global
        if trust_score > 0.8:
            factors['primary_indicators'].append({
                'type': 'Confiance élevée',
                'description': "Convergence forte entre plusieurs systèmes de détection",
                'weight': 'high'
            })
        
        return factors
    
    def _generate_recommendations(self, trust_score: float,
                                 techniques: List[Dict],
                                 event: Dict) -> List[Dict]:
        """Génère des recommandations d'action"""
        recommendations = []
        
        threat_level = self._calculate_threat_level(trust_score, 0)
        
        # Recommandations basées sur le niveau de menace
        if threat_level == 'CRITICAL':
            recommendations.append({
                'priority': 'URGENT',
                'action': 'Bloquer immédiatement',
                'description': f"Bloquer l'IP {event.get('src_ip')} au niveau du firewall",
                'rationale': "Menace critique détectée avec haute confiance"
            })
            recommendations.append({
                'priority': 'HIGH',
                'action': 'Investigation approfondie',
                'description': "Analyser les logs complets des dernières 24h pour cette IP",
                'rationale': "Identifier l'étendue potentielle de la compromission"
            })
        
        elif threat_level == 'HIGH':
            recommendations.append({
                'priority': 'HIGH',
                'action': 'Surveillance accrue',
                'description': f"Monitorer activement l'IP {event.get('src_ip')}",
                'rationale': "Activité suspecte nécessitant surveillance"
            })
            recommendations.append({
                'priority': 'MEDIUM',
                'action': 'Rate limiting',
                'description': "Appliquer des limites de taux sur cette IP",
                'rationale': "Prévenir l'escalade d'attaque"
            })
        
        elif threat_level == 'MEDIUM':
            recommendations.append({
                'priority': 'MEDIUM',
                'action': 'Enregistrer et surveiller',
                'description': "Logger l'événement pour analyse de tendances",
                'rationale': "Activité potentiellement suspecte"
            })
        
        else:  # LOW
            recommendations.append({
                'priority': 'LOW',
                'action': 'Logging standard',
                'description': "Conserver dans les logs pour référence",
                'rationale': "Faible risque identifié"
            })
        
        # Recommandations spécifiques aux techniques MITRE
        if techniques:
            tactics = set(t['tactic'] for t in techniques)
            
            if 'Credential Access' in tactics:
                recommendations.append({
                    'priority': 'HIGH',
                    'action': 'Vérification des comptes',
                    'description': "Auditer les tentatives d'accès et réinitialiser les mots de passe compromis",
                    'rationale': "Tentative d'accès aux identifiants détectée"
                })
            
            if 'Initial Access' in tactics:
                recommendations.append({
                    'priority': 'HIGH',
                    'action': 'Inspection des applications',
                    'description': "Vérifier l'intégrité des applications exposées",
                    'rationale': "Tentative d'exploitation d'application détectée"
                })
        
        return recommendations
    
    def _calculate_threat_level(self, trust_score: float, anomaly_score: float) -> str:
        """Calcule le niveau de menace"""
        max_score = max(trust_score, anomaly_score)
        
        if max_score >= 0.9:
            return 'CRITICAL'
        elif max_score >= 0.7:
            return 'HIGH'
        elif max_score >= 0.5:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _extract_kill_chain(self, techniques: List[Dict]) -> List[str]:
        """Extrait la kill chain des techniques"""
        kill_chain_order = [
            'Reconnaissance', 'Resource Development', 'Initial Access',
            'Execution', 'Persistence', 'Privilege Escalation',
            'Defense Evasion', 'Credential Access', 'Discovery',
            'Lateral Movement', 'Collection', 'Command and Control',
            'Exfiltration', 'Impact'
        ]
        
        detected_tactics = set(t['tactic'] for t in techniques)
        return [tactic for tactic in kill_chain_order if tactic in detected_tactics]
    
    def _extract_indicators(self, event: Dict, techniques: List[Dict]) -> Dict:
        """Extrait les indicateurs de compromission"""
        indicators = {
            'ip_addresses': [],
            'patterns': [],
            'techniques': []
        }
        
        # IP source
        if event.get('src_ip'):
            indicators['ip_addresses'].append(event['src_ip'])
        
        # Patterns détectés
        for tech in techniques:
            if 'matched_patterns' in tech:
                indicators['patterns'].extend(tech['matched_patterns'][:2])
        
        # IDs techniques
        indicators['techniques'] = [t['technique_id'] for t in techniques]
        
        return indicators
    
    def explain_false_positive(self, event: Dict, reason: str) -> Dict:
        """Génère une explication pour un faux positif"""
        return {
            'type': 'false_positive_explanation',
            'event_id': event.get('id'),
            'summary': 'Faux positif identifié',
            'explanation': f"Cet événement a été marqué comme faux positif. Raison: {reason}",
            'learning_point': "Cette information sera utilisée pour améliorer la calibration du système."
        }
    
    def batch_explain(self, results: List[Dict]) -> List[Dict]:
        """Génère des explications pour un batch de résultats"""
        explanations = []
        
        for result in results:
            explanation = self.explain(
                result.get('event', {}),
                result.get('mitre_techniques', []),
                result.get('anomaly_score', 0),
                result.get('trust_score', 0),
                result.get('llm_analysis')
            )
            explanations.append(explanation)
        
        return explanations

if __name__ == '__main__':
    # Test
    from lm_client import LMClient
    
    client = LMClient()
    explainer = XAIExplainer(client)
    
    # Test event
    test_event = {
        'id': 'evt_001',
        'timestamp': '2024-01-15T10:23:45Z',
        'src_ip': '203.0.113.10',
        'event_type': 'ssh_attempt',
        'message': 'Failed password for invalid user admin from 203.0.113.10 port 54321 ssh2'
    }
    
    test_techniques = [
        {
            'technique_id': 'T1110',
            'technique_name': 'Brute Force',
            'tactic': 'Credential Access',
            'confidence': 0.85,
            'matched_patterns': ['failed password', 'invalid user']
        }
    ]
    
    print("🧪 Test XAI Explainer\n")
    
    explanation = explainer.explain(
        test_event,
        test_techniques,
        anomaly_score=0.75,
        trust_score=0.82
    )
    
    print("📝 Résumé:", explanation['summary'])
    print("\n💬 Explication:")
    print(explanation['explanation'])
    print("\n📊 Niveau de menace:", explanation['scores']['threat_level'])
    print("\n🎯 Recommandations:")
    for rec in explanation['recommendations']:
        print(f"  [{rec['priority']}] {rec['action']}: {rec['description']}")