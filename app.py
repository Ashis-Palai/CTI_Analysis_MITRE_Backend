from flask import Flask, request, jsonify, send_file
import json
import re
import os
from flask_cors import CORS
from datetime import datetime

app = Flask(__name__)
CORS(app, origins=[
    "https://ashis-palai.github.io",
    "https://mango-moss-0c241dc00.6.azurestaticapps.net"
])

# Load the MITRE ATT&CK dataset
with open("enterprise-attack.json", "r", encoding="utf-8") as f:
    attack_data = json.load(f)

# Regex pattern to match attack-pattern IDs
attack_pattern_regex = r"attack-pattern--[a-f0-9\-]+"

# Search function for APT groups
def search_mitre_attack(query):
    results = []
    for obj in attack_data["objects"]:
        if query.lower() in json.dumps(obj).lower():
            results.append(obj)
    return results

# Extract unique TTPs from found objects
def extract_ttps(found_ttps):
    unique_ttps = set()
    for obj in found_ttps:
        for key in ['target_ref', 'source_ref', 'id']:
            if key in obj:
                attack_pattern_id = obj[key]
                if re.match(attack_pattern_regex, attack_pattern_id):
                    unique_ttps.add(attack_pattern_id)
    return unique_ttps

# Fetch details for an attack-pattern ID
def get_attack_pattern_details(attack_pattern_id):
    for obj in attack_data["objects"]:
        if obj.get("type") == "attack-pattern" and obj.get("id") == attack_pattern_id:
            return {
                "name": obj.get("name"),
                "kill_chain_phases": obj.get("kill_chain_phases", []),
                "external_references": obj.get("external_references", []),
            }
    return None

# Generate MITRE Navigator JSON
def generate_navigator_json(apt_ttps):
    color_mapping = ["#FF5733", "#33FF57", "#3357FF"]  # Unique colors per APT group
    overlap_color = "#FFFF00"  # Yellow for overlapping techniques

    navigator_data = {
        "name": "APT Comparison Layer",
        "layerVersion": "4.5",
        "version": {  
            "attack": "current",
            "navigator": "4.9.0",
            "layer": "4.5"
        },
        "domain": "enterprise-attack",
        "description": "TTPs comparison of selected APT groups with unique and overlapping techniques",
        "filters": {"platforms": ["Windows", "Linux", "macOS"]},
        "sorting": 3,
        "layout": {"layout": "side", "showName": True, "showID": True},
        "hideDisabled": False,
        "techniques": [],
        "gradient": {
            "colors": ["#FF5733", "#33FF57", "#3357FF", "#FFFF00"],
            "minValue": 1,
            "maxValue": 5
        },
        "legendItems": [],
        "metadata": [
            {"name": "Created By", "value": "Automated Script"},
            {"name": "Date", "value": datetime.utcnow().strftime("%Y-%m-%d")}
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#f4f4f4",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": True,
        "selectVisibleTechniques": False
    }

    # Identify unique and overlapping techniques
    all_ttps = set().union(*apt_ttps.values())
    overlap_ttps = set.intersection(*apt_ttps.values()) if len(apt_ttps) > 1 else set()

    technique_entries = {}

    for i, (apt, ttps) in enumerate(apt_ttps.items()):
        color = color_mapping[i % len(color_mapping)]  # Rotate colors if more than 3 groups
        for ttp in ttps:
            if ttp in technique_entries:
                technique_entries[ttp]["color"] = overlap_color
                technique_entries[ttp]["score"] = 5  # Higher score for overlapping
                technique_entries[ttp]["comment"] += f", {apt}"
            else:
                technique_entries[ttp] = {
                    "techniqueID": ttp,
                    "score": 2 if ttp not in overlap_ttps else 5,
                    "color": overlap_color if ttp in overlap_ttps else color,
                    "comment": f"Used by {apt}",
                    "enabled": True
                }

        # Add legend entry for each APT group
        navigator_data["legendItems"].append({"label": f"{apt} TTPs", "color": color})

    # Add legend entry for overlapping techniques
    if overlap_ttps:
        navigator_data["legendItems"].append({"label": "Common TTPs", "color": overlap_color})

    # Append finalized techniques to JSON
    navigator_data["techniques"] = list(technique_entries.values())

    # Save the JSON file
    with open("navigator.json", "w", encoding="utf-8") as f:
        json.dump(navigator_data, f, indent=4)

    return "navigator.json"

@app.route("/compare", methods=["POST"])
def compare_apt_groups():
    data = request.json
    apt_groups = data.get("apt_groups", [])
    
    if not (1 <= len(apt_groups) <= 3):
        return jsonify({"error": "Provide 1 to 3 APT group names."}), 400
    
    apt_ttps = {}
    detailed_ttps = {}
    for apt in apt_groups:
        found_ttps = search_mitre_attack(apt)
        unique_ttps = extract_ttps(found_ttps)
        apt_ttps[apt] = unique_ttps
        detailed_ttps[apt] = [get_attack_pattern_details(ttp) for ttp in unique_ttps]
    
    json_file = generate_navigator_json(apt_ttps)
    
    return jsonify({
        "apt_ttps": detailed_ttps,
        "navigator_json": request.host_url + "download"
    })

@app.route("/download", methods=["GET"])
def download_navigator_json():
    return send_file("navigator.json", as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)
