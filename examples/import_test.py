"""
Dettectinator - The Python library to your DeTT&CT YAML files.
Authors:
    Martijn Veken, Sirius Security
    Ruben Bouman, Sirius Security
License: GPL-3.0 License

This file is intended for demonstration purposes only.
"""

import os
import sys
import json
import argparse

try:
    # When dettectinator is installed as python library
    from dettectinator import DettectTechniquesAdministration
    from dettectinator.plugins.data_import import ImportCsv, ImportTaniumSignals, ImportDefenderAlerts, \
        ImportSentinelAlertRules
except ModuleNotFoundError:
    # When dettectinator is not installed as python library
    sys.path.append(os.path.dirname(os.path.abspath(__file__).replace('examples', 'dettectinator')))
    from dettectinator import DettectTechniquesAdministration
    from plugins.data_import import ImportCsv, ImportTaniumSignals, ImportDefenderAlerts, ImportSentinelAlertRules


def test_file(local_stix_path: str):
    """
    Tests an import via ImportCsv plugin.
    """
    parameters = {'file': 'import.csv'}
    import_csv = ImportCsv(parameters)
    use_cases = import_csv.get_attack_techniques(['test'], 'Test')
    print(json.dumps(use_cases, indent=4))

    dettect = DettectTechniquesAdministration(local_stix_path=local_stix_path)
    dettect.update_detections(use_cases, False, False, '', False, False)
    dettect.save_yaml_file('techniques_import_file.yaml')


def test_defender(local_stix_path: str):
    """
    Tests an import via ImportDefenderAlerts plugin.
    """
    parameters = {'app_id': '', 'tenant_id': ''}
    import_defender = ImportDefenderAlerts(parameters)
    use_cases = import_defender.get_attack_techniques(['test'], 'MD')
    print(json.dumps(use_cases, indent=4))

    dettect = DettectTechniquesAdministration(local_stix_path=local_stix_path)
    dettect.update_detections(use_cases, False, False, '', False, False)
    dettect.save_yaml_file('techniques_import_defender.yaml')


def test_tanium(local_stix_path: str):
    """
    Tests an import via ImportTaniumSignals plugin.
    """
    parameters = {'host': '', 'user': '', 'password': '', 'search_prefix': ''}
    import_tanium = ImportTaniumSignals(parameters)
    use_cases = import_tanium.get_attack_techniques(['all'], 'Tanium')
    print(json.dumps(use_cases, indent=4))

    dettect = DettectTechniquesAdministration(local_stix_path=local_stix_path)
    dettect.update_detections(use_cases, False, False, '', False, False)
    dettect.save_yaml_file('techniques_import_tanium.yaml')


def test_sentinel(local_stix_path: str):
    """
    Tests an import via ImportSentinelAlertRules plugin.
    """
    parameters = {'app_id': '', 'tenant_id': '', 'subscription_id': '', 'resource_group': '', 'workspace': ''}
    import_sentinel = ImportSentinelAlertRules(parameters)
    use_cases = import_sentinel.get_attack_techniques(['test'], 'test')
    print(json.dumps(use_cases, indent=4))

    dettect = DettectTechniquesAdministration(local_stix_path=local_stix_path)
    dettect.update_detections(use_cases, False, False, '', False, False)
    dettect.save_yaml_file('techniques_import_sentinel.yaml')


if __name__ == '__main__':
    menu_parser = argparse.ArgumentParser()
    menu_parser.add_argument('--local-stix-path', help="Path to a local STIX ATT&CK repository")
    args = menu_parser.parse_args()
    arg_local_stix_path = args.local_stix_path

    test_file(arg_local_stix_path)
    # test_defender(arg_local_stix_path)
    # test_tanium(arg_local_stix_path)
    # test_sentinel(arg_local_stix_path)
