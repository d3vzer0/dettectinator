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
import requests
import urllib3

try:
    # When dettectinator is installed as python library
    from dettectinator.plugins.support.authentication import Tanium
except ModuleNotFoundError:
    # When dettectinator is not installed as python library
    sys.path.append(os.path.dirname(os.path.abspath(__file__).replace("plugins", "")))
    from plugins.support.authentication import Tanium


# Disable SSL certificate warnings for dev purposes:
urllib3.disable_warnings()


class TechniqueTaniumSignals(TechniqueBase):
    """
    Class for importing signals with ATT&CK technique mapping from Tanium.
    """

    def __init__(self, parameters: dict) -> None:
        super().__init__(parameters)

        if "host" not in self._parameters:
            raise Exception('DetectionTaniumSignals: "host" parameter is required.')
        if "user" not in self._parameters:
            raise Exception('DetectionTaniumSignals: "user" parameter is required.')
        if "password" not in self._parameters:
            raise Exception('DetectionTaniumSignals: "password" parameter is required.')
        if "search_prefix" not in self._parameters:
            raise Exception(
                'DetectionTaniumSignals: "search_prefix" parameter is required.'
            )

        self._host = self._parameters["host"]
        self._user = self._parameters["user"]
        self._password = self._parameters["password"]
        self._search_prefix = self._parameters["search_prefix"]
        self._LOGIN_URL = "https://" + self._host + "/api/v2/session/login"
        self._INTEL_URL = (
            "https://" + self._host + "/plugin/products/detect3/api/v1/intels"
        )

        self._session = Tanium.connect_http(self._user, self._password, self._LOGIN_URL)

    @staticmethod
    def set_plugin_params(parser: ArgumentParser) -> None:
        """
        Set command line arguments specific for the plugin
        :param parser: Argument parser
        """
        TechniqueBase.set_plugin_params(parser)

        parser.add_argument("--host", help="Tanium host", required=True)
        parser.add_argument("--user", help="Tanium API username", required=True)
        parser.add_argument("--password", help="Tanium API password", required=True)
        parser.add_argument("--search_prefix", help="Search prefix")

    def get_data_from_source(self) -> Iterable:
        """
        Gets the use-case/technique data from the source.
        :return: Iterable, yields technique, detection
        """
        tanium_data = self._get_all_signals()

        for signal in tanium_data:
            if "mitreAttack" in signal.keys() and signal["mitreAttack"]:
                signal_techniques = json.loads(signal["mitreAttack"])

                for t in signal_techniques["techniques"]:
                    technique = t["id"]
                    use_case = signal["name"]
                    yield technique, use_case

    def _get_all_signals(self) -> dict:
        """
        Gets all signals (max 500 allowed by API) from Tanium.
        """
        headers = {"session": self._session, "Content-Type": "application/json"}
        params = {"limit": "500", "name": self._search_prefix}
        r = requests.get(self._INTEL_URL, params=params, headers=headers, verify=False)
        if r.status_code == requests.codes.ok:
            return r.json()
        else:
            raise Exception(f"DetectionTaniumSignals: get all signals failed: {r.text}")
