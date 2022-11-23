"""
Dettectinator - The Python library to your DeTT&CT YAML files.
Authors:
    Martijn Veken, Sirius Security
    Ruben Bouman, Sirius Security
License: GPL-3.0 License
"""

from argparse import ArgumentParser
from collections.abc import Iterable
from plugins.base.technique import TechniqueBase

class TechniqueSuricataRules(TechniqueBase):
    """
    Import data from a Suricata rules file. It expects a metadata meta-setting containing a field with the name
    mitre_technique_id containing the ATT&CK technique ID.

    https://suricata.readthedocs.io/en/latest/rules/meta.html#metadata

    Example (taken from https://rules.emergingthreats.net/open/suricata/rules/emerging-hunting.rules):
    alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET HUNTING Possible Phishing - Form submitted to submit-form Form Hosting";
    flow:established,to_server; http.method; content:"POST"; http.host; content:"submit-form.com"; endswith; classtype:credential-theft;
    sid:2030707; rev:2; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, created_at 2020_08_20, deployment Perimeter,
    former_category HUNTING, signature_severity Critical, tag Phishing, updated_at 2020_08_20, mitre_tactic_id TA0001, mitre_tactic_name Initial_Access,
    mitre_technique_id T1566, mitre_technique_name Phishing;)
    """

    def __init__(self, parameters: dict) -> None:
        super().__init__(parameters)
        if 'file' not in self._parameters:
            raise Exception('DetectionSuricateRules: "file" parameter is required.')

    @staticmethod
    def set_plugin_params(parser: ArgumentParser) -> None:
        """
        Set command line arguments specific for the plugin
        :param parser: Argument parser
        """
        TechniqueBase.set_plugin_params(parser)

        parser.add_argument('--file', help='Path of the Suricate rules file to import', required=True)

    def get_data_from_source(self) -> Iterable:
        """
        Gets the use-case/technique data from the source.
        :return: Iterable, yields technique, detection
        """
        file = self._parameters['file']
        print(f'Reading data from "{file}"')

        from suricataparser import parse_file
        rules = parse_file(file)

        for rule in rules:
            if rule.enabled:
                for option in rule.options:
                    if option.name == 'metadata':
                        meta_data = self._convert_metadata_list_to_dict(option.value.data)
                        if 'mitre_technique_id' in meta_data.keys():
                            yield meta_data['mitre_technique_id'], rule.msg

    @staticmethod
    def _convert_metadata_list_to_dict(meta_data: list) -> dict:
        """
        Converts a list with "key<space>value" into a dictionary.
        """
        meta_data_dict = {}
        for item in meta_data:
            splitted = item.split(' ')
            meta_data_dict[splitted[0]] = splitted[1]
        return meta_data_dict