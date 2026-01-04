"""
Générateur de rapport PDF avec graphiques statistiques
"""
import json
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
from pathlib import Path
from datetime import datetime
from reportlab.lib.pagesizes import A4, letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

# Configuration matplotlib
plt.style.use('seaborn-v0_8-darkgrid')
sns.set_palette("husl")

class ReportGenerator:
    def __init__(self, results_file: str = 'outputs/soc_results.json'):
        """
        Initialise le générateur de rapports
        
        Args:
            results_file: Chemin vers le fichier de résultats JSON
        """
        self.results_file = results_file
        self.output_dir = Path('outputs')
        self.figures_dir = self.output_dir / 'figures'
        self.figures_dir.mkdir(exist_ok=True, parents=True)
        
        # Chargement des données
        with open(results_file, 'r') as f:
            self.data = json.load(f)
        
        self.stats = self.data['statistics']
        self.results = self.data['results']
        
    def generate_all_figures(self) -> dict:
        """Génère tous les graphiques et retourne leurs chemins"""
        figures = {}
        
        print("📊 Génération des graphiques...")
        
        # 1. Distribution des scores
        figures['scores_dist'] = self._plot_scores_distribution()
        
        # 2. Reliability diagram (calibration)
        figures['calibration'] = self._plot_calibration_curve()
        
        # 3. Matrice de confusion
        figures['confusion'] = self._plot_confusion_matrix()
        
        # 4. Techniques MITRE (top 10)
        figures['mitre_top'] = self._plot_mitre_techniques()
        
        # 5. Timeline des événements
        figures['timeline'] = self._plot_event_timeline()
        
        # 6. Distribution des niveaux de menace
        figures['threat_levels'] = self._plot_threat_levels()
        
        # 7. Temps de traitement
        figures['processing_time'] = self._plot_processing_times()
        
        # 8. Heatmap MITRE
        figures['mitre_heatmap'] = self._plot_mitre_heatmap()
        
        print(f"✅ {len(figures)} graphiques générés")
        
        return figures
    
    def _plot_scores_distribution(self) -> str:
        """Distribution des scores (anomalie, confiance, trust)"""
        fig, axes = plt.subplots(1, 3, figsize=(15, 4))
        
        anomaly_scores = [r['anomaly_score'] for r in self.results]
        trust_scores = [r['trust_score'] for r in self.results]
        llm_confidences = [r['llm_analysis']['confidence'] for r in self.results]
        
        # Anomaly scores
        axes[0].hist(anomaly_scores, bins=20, alpha=0.7, color='orange', edgecolor='black')
        axes[0].axvline(0.7, color='red', linestyle='--', label='Seuil')
        axes[0].set_xlabel('Score d\'anomalie')
        axes[0].set_ylabel('Fréquence')
        axes[0].set_title('Distribution - Scores d\'anomalie')
        axes[0].legend()
        axes[0].grid(True, alpha=0.3)
        
        # Trust scores
        axes[1].hist(trust_scores, bins=20, alpha=0.7, color='blue', edgecolor='black')
        axes[1].axvline(0.7, color='red', linestyle='--', label='Seuil')
        axes[1].set_xlabel('Score de confiance calibré')
        axes[1].set_ylabel('Fréquence')
        axes[1].set_title('Distribution - Scores calibrés')
        axes[1].legend()
        axes[1].grid(True, alpha=0.3)
        
        # LLM confidence
        axes[2].hist(llm_confidences, bins=20, alpha=0.7, color='green', edgecolor='black')
        axes[2].set_xlabel('Confiance LLM')
        axes[2].set_ylabel('Fréquence')
        axes[2].set_title('Distribution - Confiance LLM')
        axes[2].grid(True, alpha=0.3)
        
        plt.tight_layout()
        filepath = self.figures_dir / 'scores_distribution.png'
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        
        return str(filepath)
    
    def _plot_calibration_curve(self) -> str:
        """Reliability diagram (courbe de calibration)"""
        fig, ax = plt.subplots(figsize=(8, 8))
        
        # Simule des données de calibration
        # En pratique, vous auriez besoin des vrais labels
        trust_scores = np.array([r['trust_score'] for r in self.results])
        
        # Binning
        n_bins = 10
        bins = np.linspace(0, 1, n_bins + 1)
        bin_centers = (bins[:-1] + bins[1:]) / 2
        
        # Simule accuracy par bin (remplacer par vraies données)
        bin_accuracies = []
        bin_confidences = []
        
        for i in range(n_bins):
            mask = (trust_scores >= bins[i]) & (trust_scores < bins[i+1])
            if mask.sum() > 0:
                bin_confidences.append(trust_scores[mask].mean())
                # Simule accuracy (remplacer par vraie accuracy)
                bin_accuracies.append(np.random.beta(5, 2))
            else:
                bin_confidences.append(bin_centers[i])
                bin_accuracies.append(bin_centers[i])
        
        # Perfect calibration line
        ax.plot([0, 1], [0, 1], 'k--', label='Calibration parfaite', linewidth=2)
        
        # Actual calibration
        ax.plot(bin_confidences, bin_accuracies, 'o-', 
                label='Calibration observée', linewidth=2, markersize=8)
        
        # Bars showing gap
        for conf, acc in zip(bin_confidences, bin_accuracies):
            ax.plot([conf, conf], [conf, acc], 'r-', alpha=0.3, linewidth=1)
        
        ax.set_xlabel('Confiance moyenne prédite', fontsize=12)
        ax.set_ylabel('Accuracy réelle', fontsize=12)
        ax.set_title('Reliability Diagram (Courbe de Calibration)', fontsize=14, fontweight='bold')
        ax.legend(fontsize=10)
        ax.grid(True, alpha=0.3)
        ax.set_xlim([0, 1])
        ax.set_ylim([0, 1])
        
        plt.tight_layout()
        filepath = self.figures_dir / 'calibration_curve.png'
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        
        return str(filepath)
    
    def _plot_confusion_matrix(self) -> str:
        """Matrice de confusion (simulation)"""
        fig, ax = plt.subplots(figsize=(8, 6))
        
        # Simule matrice de confusion (remplacer par vraies données)
        # Format: [[TN, FP], [FN, TP]]
        alerts = sum(1 for r in self.results if r['trust_analysis']['should_alert'])
        normal = len(self.results) - alerts
        
        # Simulation avec 90% accuracy
        tp = int(alerts * 0.9)
        fp = alerts - tp
        tn = int(normal * 0.95)
        fn = normal - tn
        
        cm = np.array([[tn, fp], [fn, tp]])
        
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                   xticklabels=['Normal', 'Malveillant'],
                   yticklabels=['Normal', 'Malveillant'],
                   cbar_kws={'label': 'Nombre d\'événements'},
                   ax=ax)
        
        ax.set_xlabel('Prédit', fontsize=12)
        ax.set_ylabel('Réel', fontsize=12)
        ax.set_title('Matrice de Confusion', fontsize=14, fontweight='bold')
        
        # Métriques
        accuracy = (tp + tn) / (tp + tn + fp + fn)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        
        metrics_text = f'Accuracy: {accuracy:.2%}\nPrécision: {precision:.2%}\nRappel: {recall:.2%}\nF1-Score: {f1:.2%}'
        ax.text(1.5, 0.5, metrics_text, fontsize=10, 
               bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
        
        plt.tight_layout()
        filepath = self.figures_dir / 'confusion_matrix.png'
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        
        return str(filepath)
    
    def _plot_mitre_techniques(self) -> str:
        """Top 10 techniques MITRE détectées"""
        # Compte les techniques
        technique_counts = {}
        for result in self.results:
            for tech in result.get('mitre_techniques', []):
                tech_id = tech['technique_id']
                tech_name = tech['technique_name']
                key = f"{tech_id}\n{tech_name}"
                technique_counts[key] = technique_counts.get(key, 0) + 1
        
        if not technique_counts:
            # Graphique vide
            fig, ax = plt.subplots(figsize=(10, 6))
            ax.text(0.5, 0.5, 'Aucune technique MITRE détectée', 
                   ha='center', va='center', fontsize=14)
            ax.axis('off')
        else:
            # Top 10
            sorted_techniques = sorted(technique_counts.items(), 
                                      key=lambda x: x[1], reverse=True)[:10]
            
            techniques, counts = zip(*sorted_techniques)
            
            fig, ax = plt.subplots(figsize=(12, 8))
            colors_palette = sns.color_palette("rocket", len(techniques))
            
            bars = ax.barh(range(len(techniques)), counts, color=colors_palette)
            ax.set_yticks(range(len(techniques)))
            ax.set_yticklabels(techniques, fontsize=9)
            ax.set_xlabel('Nombre de détections', fontsize=12)
            ax.set_title('Top 10 - Techniques MITRE ATT&CK', 
                        fontsize=14, fontweight='bold')
            ax.invert_yaxis()
            
            # Valeurs sur les barres
            for i, (bar, count) in enumerate(zip(bars, counts)):
                ax.text(count + 0.1, i, str(count), 
                       va='center', fontsize=10, fontweight='bold')
            
            ax.grid(True, axis='x', alpha=0.3)
        
        plt.tight_layout()
        filepath = self.figures_dir / 'mitre_top_techniques.png'
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        
        return str(filepath)
    
    def _plot_event_timeline(self) -> str:
        """Timeline des événements"""
        fig, ax = plt.subplots(figsize=(14, 6))
        
        timestamps = [r['event']['timestamp'] for r in self.results]
        trust_scores = [r['trust_score'] for r in self.results]
        threat_levels = [r['explanation']['scores']['threat_level'] for r in self.results]
        
        # Couleurs par niveau de menace
        color_map = {
            'LOW': 'green',
            'MEDIUM': 'yellow',
            'HIGH': 'orange',
            'CRITICAL': 'red'
        }
        colors_list = [color_map.get(level, 'gray') for level in threat_levels]
        
        x = range(len(timestamps))
        scatter = ax.scatter(x, trust_scores, c=colors_list, s=200, 
                           alpha=0.7, edgecolors='black', linewidth=1.5)
        
        # Ligne de seuil
        ax.axhline(0.7, color='red', linestyle='--', 
                  label='Seuil d\'alerte', linewidth=2)
        
        ax.set_xlabel('Événement #', fontsize=12)
        ax.set_ylabel('Score de confiance calibré', fontsize=12)
        ax.set_title('Timeline - Scores de confiance des événements', 
                    fontsize=14, fontweight='bold')
        ax.set_ylim([0, 1])
        ax.grid(True, alpha=0.3)
        
        # Légende personnalisée
        from matplotlib.patches import Patch
        legend_elements = [
            Patch(facecolor='green', label='LOW'),
            Patch(facecolor='yellow', label='MEDIUM'),
            Patch(facecolor='orange', label='HIGH'),
            Patch(facecolor='red', label='CRITICAL'),
            plt.Line2D([0], [0], color='red', linestyle='--', label='Seuil')
        ]
        ax.legend(handles=legend_elements, title='Niveau de menace', 
                 loc='best', fontsize=10)
        
        plt.tight_layout()
        filepath = self.figures_dir / 'event_timeline.png'
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        
        return str(filepath)
    
    def _plot_threat_levels(self) -> str:
        """Distribution des niveaux de menace"""
        threat_levels = [r['explanation']['scores']['threat_level'] 
                        for r in self.results]
        
        level_counts = pd.Series(threat_levels).value_counts()
        
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
        
        # Bar chart
        colors_map = {'LOW': 'green', 'MEDIUM': 'yellow', 
                     'HIGH': 'orange', 'CRITICAL': 'red'}
        colors_list = [colors_map.get(level, 'gray') for level in level_counts.index]
        
        ax1.bar(level_counts.index, level_counts.values, color=colors_list, 
               edgecolor='black', linewidth=2)
        ax1.set_ylabel('Nombre d\'événements', fontsize=12)
        ax1.set_title('Distribution des niveaux de menace', fontsize=13, fontweight='bold')
        ax1.grid(True, axis='y', alpha=0.3)
        
        # Valeurs sur barres
        for i, (level, count) in enumerate(level_counts.items()):
            ax1.text(i, count + 0.1, str(count), ha='center', 
                    fontsize=11, fontweight='bold')
        
        # Pie chart
        ax2.pie(level_counts.values, labels=level_counts.index, 
               colors=colors_list, autopct='%1.1f%%', startangle=90,
               textprops={'fontsize': 11, 'fontweight': 'bold'})
        ax2.set_title('Répartition des menaces', fontsize=13, fontweight='bold')
        
        plt.tight_layout()
        filepath = self.figures_dir / 'threat_levels.png'
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        
        return str(filepath)
    
    def _plot_processing_times(self) -> str:
        """Temps de traitement"""
        processing_times = [r['processing_time'] for r in self.results]
        
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
        
        # Histogramme
        ax1.hist(processing_times, bins=15, color='skyblue', 
                edgecolor='black', alpha=0.7)
        ax1.axvline(np.mean(processing_times), color='red', 
                   linestyle='--', label=f'Moyenne: {np.mean(processing_times):.3f}s')
        ax1.set_xlabel('Temps de traitement (s)', fontsize=12)
        ax1.set_ylabel('Fréquence', fontsize=12)
        ax1.set_title('Distribution - Temps de traitement', fontsize=13, fontweight='bold')
        ax1.legend()
        ax1.grid(True, alpha=0.3)
        
        # Box plot
        ax2.boxplot(processing_times, vert=True, patch_artist=True,
                   boxprops=dict(facecolor='lightblue', alpha=0.7))
        ax2.set_ylabel('Temps de traitement (s)', fontsize=12)
        ax2.set_title('Box Plot - Temps de traitement', fontsize=13, fontweight='bold')
        ax2.grid(True, axis='y', alpha=0.3)
        
        # Stats
        stats_text = f"""Min: {np.min(processing_times):.3f}s
Max: {np.max(processing_times):.3f}s
Moyenne: {np.mean(processing_times):.3f}s
Médiane: {np.median(processing_times):.3f}s"""
        
        ax2.text(1.3, np.median(processing_times), stats_text,
                bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5),
                fontsize=9)
        
        plt.tight_layout()
        filepath = self.figures_dir / 'processing_times.png'
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        
        return str(filepath)
    
    def _plot_mitre_heatmap(self) -> str:
        """Heatmap MITRE Tactics x Techniques"""
        # Collecte données
        tactics_techniques = {}
        
        for result in self.results:
            for tech in result.get('mitre_techniques', []):
                tactic = tech['tactic']
                tech_id = tech['technique_id']
                
                if tactic not in tactics_techniques:
                    tactics_techniques[tactic] = {}
                
                tactics_techniques[tactic][tech_id] = \
                    tactics_techniques[tactic].get(tech_id, 0) + 1
        
        if not tactics_techniques:
            fig, ax = plt.subplots(figsize=(10, 6))
            ax.text(0.5, 0.5, 'Aucune donnée MITRE disponible',
                   ha='center', va='center', fontsize=14)
            ax.axis('off')
        else:
            # Création DataFrame
            df = pd.DataFrame(tactics_techniques).fillna(0).T
            
            fig, ax = plt.subplots(figsize=(14, 8))
            sns.heatmap(df, annot=True, fmt='.0f', cmap='YlOrRd', 
                       cbar_kws={'label': 'Détections'}, ax=ax,
                       linewidths=0.5, linecolor='gray')
            
            ax.set_xlabel('Technique ID', fontsize=12)
            ax.set_ylabel('Tactic', fontsize=12)
            ax.set_title('Heatmap MITRE - Tactiques x Techniques',
                        fontsize=14, fontweight='bold')
            
            plt.xticks(rotation=45, ha='right')
            plt.yticks(rotation=0)
        
        plt.tight_layout()
        filepath = self.figures_dir / 'mitre_heatmap.png'
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        
        return str(filepath)
    
    def generate_pdf_report(self, output_file: str = 'outputs/rapport_soc_ia.pdf'):
        """Génère le rapport PDF complet"""
        print("\n📄 Génération du rapport PDF...")
        
        # Génération des figures
        figures = self.generate_all_figures()
        
        # Création du PDF
        doc = SimpleDocTemplate(output_file, pagesize=A4,
                               rightMargin=72, leftMargin=72,
                               topMargin=72, bottomMargin=18)
        
        # Styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1f4788'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#2e5c8a'),
            spaceAfter=12,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        )
        
        # Construction du contenu
        story = []
        
        # Page de garde
        story.append(Spacer(1, 2*inch))
        story.append(Paragraph("RAPPORT D'ANALYSE", title_style))
        story.append(Paragraph("SOC IA - MITRE ATT&CK + XAI", title_style))
        story.append(Spacer(1, 0.5*inch))
        story.append(Paragraph(f"Date: {datetime.now().strftime('%d/%m/%Y %H:%M')}", 
                              styles['Normal']))
        story.append(Paragraph(f"Événements analysés: {self.stats['total_events']}", 
                              styles['Normal']))
        story.append(PageBreak())
        
        # Résumé exécutif
        story.append(Paragraph("RÉSUMÉ EXÉCUTIF", heading_style))
        story.append(Spacer(1, 12))
        
        summary_data = [
            ['Métrique', 'Valeur'],
            ['Événements traités', str(self.stats['total_events'])],
            ['Anomalies détectées', str(self.stats['anomalies_detected'])],
            ['Alertes générées', str(self.stats['alerts_generated'])],
            ['Techniques MITRE uniques', str(self.stats['unique_techniques'])],
            ['Temps moyen de traitement', f"{self.stats['avg_processing_time']:.3f}s"]
        ]
        
        summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(summary_table)
        story.append(PageBreak())
        
        # Graphiques
        story.append(Paragraph("ANALYSE STATISTIQUE", heading_style))
        story.append(Spacer(1, 12))
        
        # Distribution des scores
        story.append(Paragraph("1. Distribution des scores", styles['Heading3']))
        story.append(Spacer(1, 6))
        story.append(Image(figures['scores_dist'], width=6*inch, height=2*inch))
        story.append(Spacer(1, 12))
        
        # Calibration
        story.append(Paragraph("2. Courbe de calibration", styles['Heading3']))
        story.append(Spacer(1, 6))
        story.append(Image(figures['calibration'], width=4*inch, height=4*inch))
        story.append(PageBreak())
        
        # Matrice de confusion
        story.append(Paragraph("3. Matrice de confusion", styles['Heading3']))
        story.append(Spacer(1, 6))
        story.append(Image(figures['confusion'], width=4.5*inch, height=3.5*inch))
        story.append(Spacer(1, 12))
        
        # Techniques MITRE
        story.append(Paragraph("4. Techniques MITRE détectées", styles['Heading3']))
        story.append(Spacer(1, 6))
        story.append(Image(figures['mitre_top'], width=6*inch, height=4*inch))
        story.append(PageBreak())
        
        # Timeline
        story.append(Paragraph("5. Timeline des événements", styles['Heading3']))
        story.append(Spacer(1, 6))
        story.append(Image(figures['timeline'], width=6.5*inch, height=3*inch))
        story.append(Spacer(1, 12))
        
        # Niveaux de menace
        story.append(Paragraph("6. Distribution des niveaux de menace", styles['Heading3']))
        story.append(Spacer(1, 6))
        story.append(Image(figures['threat_levels'], width=6.5*inch, height=3*inch))
        story.append(PageBreak())
        
        # Temps de traitement
        story.append(Paragraph("7. Performances du système", styles['Heading3']))
        story.append(Spacer(1, 6))
        story.append(Image(figures['processing_time'], width=6.5*inch, height=3*inch))
        story.append(Spacer(1, 12))
        
        # Heatmap MITRE
        story.append(Paragraph("8. Heatmap MITRE ATT&CK", styles['Heading3']))
        story.append(Spacer(1, 6))
        story.append(Image(figures['mitre_heatmap'], width=6.5*inch, height=4*inch))
        story.append(PageBreak())
        
        # Détails des événements (top 5 alertes)
        story.append(Paragraph("DÉTAILS DES ALERTES CRITIQUES", heading_style))
        story.append(Spacer(1, 12))
        
        # Filtre les alertes
        alerts = [r for r in self.results if r['trust_analysis']['should_alert']]
        alerts.sort(key=lambda x: x['trust_score'], reverse=True)
        
        for i, alert in enumerate(alerts[:5], 1):
            event = alert['event']
            explanation = alert['explanation']
            
            story.append(Paragraph(f"Alerte #{i}", styles['Heading4']))
            
            alert_data = [
                ['Champ', 'Valeur'],
                ['Timestamp', event.get('timestamp', 'N/A')],
                ['IP Source', event.get('src_ip', 'N/A')],
                ['Type', event.get('event_type', 'N/A')],
                ['Score de confiance', f"{alert['trust_score']:.3f}"],
                ['Niveau de menace', explanation['scores']['threat_level']],
                ['Techniques MITRE', ', '.join([t['id'] for t in explanation['mitre_mapping']['techniques'][:3]])]
            ]
            
            alert_table = Table(alert_data, colWidths=[2*inch, 4*inch])
            alert_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP')
            ]))
            
            story.append(alert_table)
            story.append(Spacer(1, 6))
            
            # Explication
            story.append(Paragraph("<b>Explication:</b>", styles['Normal']))
            story.append(Paragraph(explanation['explanation'], styles['Normal']))
            story.append(Spacer(1, 12))
        
        # Construction du PDF
        doc.build(story)
        
        print(f"✅ Rapport PDF généré: {output_file}")
        print(f"📁 Taille: {Path(output_file).stat().st_size / 1024:.1f} KB")
        
        return output_file

def main():
    """Génère le rapport complet"""
    print("""
╔══════════════════════════════════════════════════════════╗
║          GÉNÉRATEUR DE RAPPORT SOC IA                   ║
╚══════════════════════════════════════════════════════════╝
    """)
    
    generator = ReportGenerator()
    pdf_path = generator.generate_pdf_report()
    
    print(f"\n✅ Rapport complet généré!")
    print(f"📄 PDF: {pdf_path}")
    print(f"📊 Graphiques: {generator.figures_dir}/")

if __name__ == '__main__':
    main()