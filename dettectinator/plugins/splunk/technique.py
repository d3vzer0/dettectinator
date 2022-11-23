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
import json
import os
import sys
import urllib3

try:
    # When dettectinator is installed as python library
    from dettectinator.plugins.support.authentication import Azure, Tanium
except ModuleNotFoundError:
    # When dettectinator is not installed as python library
    sys.path.append(os.path.dirname(os.path.abspath(__file__).replace('plugins', '')))
    from plugins.support.authentication import Azure, Tanium


# Disable SSL certificate warnings for dev purposes:
urllib3.disable_warnings()



class TechniqueSplunkConfigSearches(TechniqueBase):
    """
    Import data from a Splunk config that contains saved searches (savedsearches.conf). It uses
    the action.correlationsearch.annotations attribute to get the mitre_attack techniques:

    action.correlationsearch.annotations = {"mitre_attack": ["T1560.001", "T1560"]}

    Searches that contain an action.correlationsearch.label and don't have disabled=1 are included.
    """

    def __init__(self, parameters: dict) -> None:
        super().__init__(parameters)
        if 'file' not in self._parameters:
            raise Exception('DetectionSplunkConfigSearches: "file" parameter is required.')

    @staticmethod
    def set_plugin_params(parser: ArgumentParser) -> None:
        """
        Set command line arguments specific for the plugin
        :param parser: Argument parser
        """
        TechniqueBase.set_plugin_params(parser)

        parser.add_argument('--file', help='Path of the savedsearches config file to import', required=True)

    def get_data_from_source(self) -> Iterable:
        """
        Gets the use-case/technique data from the source.
        :return: Iterable, yields technique, detection
        """
        file = self._parameters['file']
        print(f'Reading data from "{file}"')

        import addonfactory_splunk_conf_parser_lib as splunk_conf_parser

        with open(file, "r") as f:
            splunk_config = splunk_conf_parser.TABConfigParser()
            splunk_config.read_file(f)

        ignore_list = ['default']
        for section in splunk_config.sections():
            if splunk_config[section].name in ignore_list \
               or 'action.correlationsearch.label' not in splunk_config[section].keys() \
               or 'action.correlationsearch.annotations' not in splunk_config[section].keys() \
               or ('disabled' in splunk_config[section].keys() and splunk_config[section]['disabled'] == '1'):
                continue

            try:
                annotations = json.loads(splunk_config[section]['action.correlationsearch.annotations'])
            except Exception as e:
                print(f'Could not parse mitre_attack entry in action.correlationsearch.annotations ({str(e)}): {splunk_config[section].name}')
            else:
                if 'mitre_attack' in annotations.keys():
                    for technique in annotations['mitre_attack']:
                        yield technique, splunk_config[section].name
