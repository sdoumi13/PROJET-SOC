from flask import Flask, render_template, abort
import json
import os
import pandas as pd
from datetime import datetime

app = Flask(__name__)

# Configuration
RESULTS_FILE = 'outputs/soc_results.json'
MATRIX_FILE = 'outputs/mitre_matrix.csv'

def load_results():
    """Charge les résultats JSON générés par le pipeline"""
    if not os.path.exists(RESULTS_FILE):
        return None
    with open(RESULTS_FILE, 'r') as f:
        return json.load(f)

def load_mitre_matrix():
    """Charge la matrice MITRE CSV"""
    if not os.path.exists(MATRIX_FILE):
        return None
    # Lire le CSV avec pandas et le convertir en liste de dictionnaires
    df = pd.read_csv(MATRIX_FILE)
    return df.to_dict(orient='records')

@app.template_filter('datetimeformat')
def datetimeformat(value, format='%d/%m/%Y %H:%M'):
    """Filtre pour formater les dates dans les templates"""
    try:
        # Adapter le parsing selon le format exact dans votre JSON
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return dt.strftime(format)
    except:
        return value

@app.route('/')
def dashboard():
    data = load_results()
    if not data:
        return render_template('error.html', message="Aucun résultat trouvé. Lancez main.py d'abord.")
    
    mitre_data = load_mitre_matrix()
    
    return render_template('index.html', 
                         stats=data.get('statistics', {}), 
                         events=data.get('results', []),
                         mitre_matrix=mitre_data,
                         last_update=data.get('timestamp'))

@app.route('/event/<event_id>')
def event_detail(event_id):
    data = load_results()
    if not data:
        return abort(404)
    
    # Trouver l'événement spécifique
    event_data = next((item for item in data['results'] if item['event']['id'] == event_id), None)
    
    if not event_data:
        return abort(404)
        
    return render_template('detail.html', result=event_data)

if __name__ == '__main__':
    print("🚀 Interface SOC lancée sur http://127.0.0.1:5000")
    app.run(debug=True, port=5000)