from flask import Flask, request, jsonify, send_file
import json
import re
import os

app = Flask(__name__)

# Load the MITRE ATT&CK dataset
with open("enterprise-attack.json", "r", encoding="utf-8") as f:
    attack_data = json.load(f)

# Regex pattern to match attack-pattern IDs
attack_pattern_regex = r"attack-pattern--[a-f0-9\-]+"

# Search function for APT groups

def search_mitre_attack(query):
    results = []
    for obj in attack_data["objects"]:
        obj_text = json.dumps(obj).lower()
        if query.lower() in obj_text:
            results.append(obj)
    return results

# Extract unique TTPs
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
                "kill_chain_phases": obj.get("kill_chain_phases"),
                "external_references": obj.get("external_references"),
            }
    return None

# Generate MITRE Navigator JSON
def generate_navigator_json(apt_ttps):
    color_mapping = ["#FF5733", "#33FF57", "#3357FF"]
    navigator_data = {"version": "2.2", "domain": "enterprise-attack", "techniques": []}

    # Determine overlapping and distinct TTPs
    all_ttps = set().union(*apt_ttps.values())
    overlap_ttps = set.intersection(*apt_ttps.values()) if len(apt_ttps) > 1 else set()
    
    for i, (apt, ttps) in enumerate(apt_ttps.items()):
        for ttp in ttps:
            technique = {
                "techniqueID": ttp,
                "color": "#FFFF00" if ttp in overlap_ttps else color_mapping[i],
                "comment": f"Used by {apt}"
            }
            navigator_data["techniques"].append(technique)
    
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
    return jsonify({"apt_ttps": detailed_ttps, "navigator_json": "/download"})

@app.route("/download", methods=["GET"])
def download_navigator_json():
    return send_file("navigator.json", as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)
