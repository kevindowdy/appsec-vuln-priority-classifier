import pandas as pd
import os


def classify(severity):
    if severity in ['Critical', 'High']:
        return 'P1'
    elif severity in ['Medium', 'Low']:
        return 'P2'
    else:
        return 'Other'

def main():

    username = "" ## REPLACE WITH USERNAME
    base_path = f"C:/Users/{username}/Downloads"

    print("loading war room data...")

    # Load war room CSVs
    war1e = pd.read_csv(f'{base_path}/APPLICATION - Insight Export - Tue May 19 2026 - Priority - 1e OWASP Top 10.csv', dtype=str)
    war7a = pd.read_csv(f'{base_path}/APPLICATION - Insight Export - Tue May 19 2026 - Priority - 7a OWASP Top 10 - Tier 1.csv', dtype=str)
    war7b = pd.read_csv(f'{base_path}/APPLICATION - Insight Export - Tue May 19 2026 - Priority - 7b OWASP Top 10 - Tier 2.csv', dtype=str)

    print("finished loading war room data")

    war_room_data = pd.concat([war1e, war7a, war7b], ignore_index=True)

    print("loading open C/H/M vulnerability data...")

    # Load c/h/m vulnerabilities
    chm_vulnerabilities = pd.read_excel(f'{base_path}/FIG Open Vulnerabilities_20260515.xlsx', sheet_name='FIG Open Vulnerabilities', dtype=str)
    chm_vulnerabilities = chm_vulnerabilities.dropna(how='all')

    print("there are " + str(len(chm_vulnerabilities)) + " chm vulnerabilities")
    print("loading open low vulnerability data...")

    # Load low vulnerabilities
    low_vulnerabilities = pd.read_excel(f'{base_path}/FIG Open Vulnerabilities_Low_2026052026.xlsx', sheet_name='FIG Open Vulnerabilities', dtype=str)
    low_vulnerabilities = low_vulnerabilities.dropna(how='all')

    print("there are " + str(len(low_vulnerabilities)) + " low vulnerabilities")

    total_open_vulnerabilities = pd.concat([chm_vulnerabilities, low_vulnerabilities], ignore_index=True)

    print("there are " + str(len(total_open_vulnerabilities)) + " vulnerabilities in total")

    print("loading app inventory")

    # Load enriched inventory
    inventory = pd.read_excel(f'{base_path}/App Inventory_Enriched 1.xlsx', dtype=str)

    print("finished loading the data")

    # Create unique hashes

    # WAR ROOM hash
    war_room_data['hash'] = (
        war_room_data['App ID'].str.strip() +
        war_room_data['Release Version'].str.strip() +
        war_room_data['Instance ID'].str.strip()
    )

    # TOTAL hash
    total_open_vulnerabilities['hash'] = (
        total_open_vulnerabilities['saltminer.inventory_asset.attributes.appmap.apm_number'].str.strip() +
        total_open_vulnerabilities['saltminer.asset.version'].str.strip() +
        total_open_vulnerabilities['saltminer.attributes.issue_instance_id'].str.strip()
    )

    war_hashes = set(war_room_data['hash'])

    filtered = total_open_vulnerabilities[~total_open_vulnerabilities['hash'].isin(war_hashes)].copy()

    filtered = filtered.merge(
        inventory[['Number', 'MC2 enriched']],
        left_on='saltminer.inventory_asset.attributes.appmap.apm_number',
        right_on='Number',
        how='left'
    )

    filtered['Priority'] = filtered['vulnerability.severity'].apply(classify)

    filtered.to_csv(f'{base_path}/Vulnerabilities-excluding-war-room.csv', index=False)
    
    print("finished generating data set")

    return

main()
