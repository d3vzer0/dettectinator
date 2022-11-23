"""
Dettectinator - The Python library to your DeTT&CT YAML files.
Authors:
    Martijn Veken, Sirius Security
    Ruben Bouman, Sirius Security
License: GPL-3.0 License
"""

from argparse import ArgumentParser
from collections.abc import Iterable
import json
import os
import sys
import re
import requests
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


class TechniqueBase:
    """
    Base class for importing use-case/technique data
    """

    def __init__(self, parameters: dict) -> None:
        self._parameters = parameters

        self._re_include = self._parameters.get('re_include', None)
        self._re_exclude = self._parameters.get('re_exclude', None)

    @staticmethod
    def set_plugin_params(parser: ArgumentParser) -> None:
        """
        Set command line arguments specific for the plugin
        :param parser: Argument parser
        """
        parser.add_argument('-l', '--location_prefix',
                            help='Location of the detection, will be prepended to the detection name.', default='')

    def get_attack_techniques(self, applicable_to: list, location_prefix: str) -> dict:
        """
        Retrieves use-case/technique data from a data source
        :param applicable_to: Systems that the detections are applicable to
        :param location_prefix: Location of the detection, will be prepended to the detection name.
        :return: Dictionary, example: {'Detection A': {'applicable_to': ['all'], 'location_prefix': 'SIEM', 'techniques': ['T1055']}}
        """

        use_cases = {}

        for technique, use_case in self.get_data_from_source():
            # Exclude all detections that match the exclude-pattern
            if self._re_exclude and not re.match(self._re_exclude, use_case) is None:
                continue

            # Include all detections that match the include-pattern
            if self._re_include and re.match(self._re_include, use_case) is None:
                continue

            if use_case in use_cases.keys():
                use_cases[use_case]['techniques'].append(technique)
            else:
                use_cases[use_case] = {'applicable_to': applicable_to,
                                       'location_prefix': location_prefix,
                                       'techniques': [technique]}

        return use_cases

    def get_data_from_source(self) -> Iterable:
        """
        Gets the use-case/technique data from the source.
        :return: Iterable, yields technique, detection
        """
        raise NotImplementedError()