#!/bin/bash

# Script de lancement complet du SOC IA
# chmod +x run_all.sh

echo "╔══════════════════════════════════════════════════════════╗"
echo "║          SOC IA - SETUP & EXECUTION COMPLÈTE             ║"
echo "║    Ateliers A (Trust) + C (Anomaly) + D (MITRE+XAI)     ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Fonction d'erreur
error_exit() {
    echo -e "${RED}❌ Erreur: $1${NC}" >&2
    exit 1
}

# Fonction de succès
success() {
    echo -e "${GREEN}✅ $1${NC}"
}

# Fonction d'info
info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Fonction d'avertissement
warn() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

# 1. Vérification Python
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "1. Vérification de l'environnement"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if ! command -v python3 &> /dev/null; then
    error_exit "Python 3 n'est pas installé"
fi

PYTHON_VERSION=$(python3 --version | awk '{print $2}')
info "Python version: $PYTHON_VERSION"

# 2. Création de l'environnement virtuel
if [ ! -d "venv" ]; then
    info "Création de l'environnement virtuel..."
    python3 -m venv venv || error_exit "Échec création venv"
    success "Environnement virtuel créé"
else
    info "Environnement virtuel existant trouvé"
fi

# Activation
source venv/bin/activate || error_exit "Échec activation venv"
success "Environnement virtuel activé"

# 3. Installation des dépendances
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "2. Installation des dépendances"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

info "Installation des packages..."
pip install --upgrade pip > /dev/null 2>&1
pip install -r requirements.txt || error_exit "Échec installation dépendances"
success "Dépendances installées"

# 4. Vérification LM Studio
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "3. Vérification LM Studio"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if curl -s http://localhost:1234/v1/models > /dev/null 2>&1; then
    success "LM Studio est accessible sur http://localhost:1234"
else
    warn "LM Studio ne répond pas sur http://localhost:1234"
    warn "Assurez-vous que LM Studio est lancé avec un modèle chargé"
    echo ""
    echo "   Modèles recommandés:"
    echo "   • Llama 3.1 8B Instruct"
    echo "   • Mistral 7B Instruct v0.2"
    echo "   • Phi-3 Medium"
    echo ""
    read -p "Continuer quand même? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        error_exit "LM Studio requis pour continuer"
    fi
fi

# 5. Création de la structure
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "4. Création de la structure de fichiers"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

mkdir -p agents data outputs outputs/figures notebooks

success "Structure créée"

# 6. Chargement de la base MITRE
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "5. Chargement de la base MITRE ATT&CK"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ ! -f "data/mitre_db.csv" ]; then
    info "Téléchargement de la base MITRE..."
    python3 data/mitre_db_loader.py || warn "Échec téléchargement MITRE (une base minimale sera créée)"
    success "Base MITRE chargée"
else
    info "Base MITRE existante trouvée"
fi

# 7. Entraînement du modèle d'anomalie (optionnel)
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "6. Entraînement du modèle de détection d'anomalies"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ ! -f "data/anomaly_model.pkl" ]; then
    warn "Modèle d'anomalie non trouvé"
    read -p "Voulez-vous lancer l'entraînement? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        info "Lancement du notebook d'entraînement..."
        echo "Exécutez: jupyter notebook notebooks/train_anomaly_detector.ipynb"
        echo "Ou convertissez et exécutez le notebook en script Python"
        warn "Un modèle par défaut sera utilisé si non entraîné"
    fi
else
    success "Modèle d'anomalie trouvé"
fi

# 8. Exécution du pipeline principal
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "7. Exécution du pipeline SOC IA"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

read -p "Lancer le pipeline principal? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    info "Lancement du pipeline..."
    python3 main.py || error_exit "Échec exécution pipeline"
    success "Pipeline terminé"
fi

# 9. Génération du rapport
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "8. Génération du rapport PDF"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

if [ -f "outputs/soc_results.json" ]; then
    read -p "Générer le rapport PDF avec graphiques? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        info "Génération du rapport..."
        python3 report_generator.py || error_exit "Échec génération rapport"
        success "Rapport généré"
    fi
else
    warn "Aucun résultat trouvé. Exécutez d'abord main.py"
fi

# 10. Résumé
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ INSTALLATION ET EXÉCUTION TERMINÉES"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📁 Fichiers générés:"
echo ""

if [ -f "outputs/soc_results.json" ]; then
    echo "   ✓ outputs/soc_results.json"
fi

if [ -f "outputs/mitre_matrix.csv" ]; then
    echo "   ✓ outputs/mitre_matrix.csv"
fi

if [ -f "outputs/mitre_navigator.json" ]; then
    echo "   ✓ outputs/mitre_navigator.json"
    echo "     → Visualiser sur: https://mitre-attack.github.io/attack-navigator/"
fi

if [ -f "outputs/rapport_soc_ia.pdf" ]; then
    echo "   ✓ outputs/rapport_soc_ia.pdf"
    
    # Affiche la taille
    SIZE=$(du -h outputs/rapport_soc_ia.pdf | cut -f1)
    echo "     (Taille: $SIZE)"
fi

if [ -d "outputs/figures" ]; then
    COUNT=$(ls -1 outputs/figures/*.png 2>/dev/null | wc -l)
    if [ $COUNT -gt 0 ]; then
        echo "   ✓ outputs/figures/ ($COUNT graphiques)"
    fi
fi

echo ""
echo "📚 Prochaines étapes:"
echo ""
echo "   1. Consulter le rapport PDF: outputs/rapport_soc_ia.pdf"
echo "   2. Visualiser la matrice MITRE sur Attack Navigator"
echo "   3. Analyser les résultats JSON: outputs/soc_results.json"
echo "   4. Améliorer la calibration avec plus de données"
echo ""
echo "🔧 Commandes utiles:"
echo ""
echo "   # Relancer le pipeline"
echo "   python3 main.py"
echo ""
echo "   # Régénérer le rapport"
echo "   python3 report_generator.py"
echo ""
echo "   # Entraîner le modèle d'anomalie"
echo "   jupyter notebook notebooks/train_anomaly_detector.ipynb"
echo ""
echo "   # Tester un agent individuel"
echo "   cd agents && python3 <agent_name>.py"
echo ""

success "Terminé!"