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
import requests
import urllib3


# Disable SSL certificate warnings for dev purposes:
urllib3.disable_warnings()


class TechniqueElasticSecurityRules(TechniqueBase):
    """
    Class for importing Elastic Security rules with ATT&CK technique mapping.
    """

    def __init__(self, parameters: dict) -> None:
        super().__init__(parameters)

        if "host" not in self._parameters:
            raise Exception(
                'DetectionElasticSecurityRules: "host" parameter is required.'
            )
        if "user" not in self._parameters:
            raise Exception(
                'DetectionElasticSecurityRules: "user" parameter is required.'
            )
        if "password" not in self._parameters:
            raise Exception(
                'DetectionElasticSecurityRules: "password" parameter is required.'
            )

        self._host = self._parameters["host"]
        self._user = self._parameters["user"]
        self._password = self._parameters["password"]
        self._filter = self._parameters["filter"]
        self._FIND_URL = "https://" + self._host + "/api/detection_engine/rules/_find"

    @staticmethod
    def set_plugin_params(parser: ArgumentParser) -> None:
        """
        Set command line arguments specific for the plugin
        :param parser: Argument parser
        """
        TechniqueBase.set_plugin_params(parser)

        parser.add_argument("--host", help="Elastic Security host", required=True)
        parser.add_argument("--user", help="Elastic Security username", required=True)
        parser.add_argument(
            "--password", help="Elastic Security password", required=True
        )
        parser.add_argument(
            "--filter",
            help="Search filter, see Elastic documentation for more information",
        )

    def get_data_from_source(self) -> Iterable:
        """
        Gets the use-case/technique data from the source.
        :return: Iterable, yields technique, detection
        """
        rule_data = self._get_all_rules()

        for rule in rule_data["data"]:
            if "threat" in rule.keys():
                for threat in rule["threat"]:
                    if (
                        threat["framework"] == "MITRE ATT&CK"
                        and "technique" in threat.keys()
                    ):
                        for tech in threat["technique"]:
                            if (
                                "subtechnique" in tech.keys()
                                and len(tech["subtechnique"]) > 0
                            ):
                                for subtech in tech["subtechnique"]:
                                    technique = subtech["id"]
                                    use_case = rule["name"]
                                    yield technique, use_case
                            else:
                                technique = tech["id"]
                                use_case = rule["name"]
                                yield technique, use_case

    def _get_all_rules(self):
        headers = {"kbn-xsrf": "dettect", "Content-Type": "application/json"}
        params = {"per_page": "10000"}
        if self._filter:
            params["filter"] = self._filter
        r = requests.get(
            self._FIND_URL,
            params=params,
            headers=headers,
            auth=(self._user, self._password),
            verify=False,
        )
        if r.status_code == requests.codes.ok:
            return r.json()
        else:
            raise Exception(
                f"DetectionElasticSecurityRules: get all rules failed: {r.text}"
            )
