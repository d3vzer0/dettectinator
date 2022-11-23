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
import re
import requests


class TechniqueDefenderIdentityRules(TechniqueBase):
    """
    Import rules for Microsoft Defender for Identity from their Github webpage:
    https://github.com/MicrosoftDocs/ATADocs/tree/master/ATPDocs
    More info:
    https://learn.microsoft.com/en-us/defender-for-identity/alerts-overview
    """

    def __init__(self, parameters: dict) -> None:
        super().__init__(parameters)

        self.ATP_DOCS = [
            "https://raw.githubusercontent.com/MicrosoftDocs/ATADocs/master/ATPDocs/compromised-credentials-alerts.md",
            "https://raw.githubusercontent.com/MicrosoftDocs/ATADocs/master/ATPDocs/domain-dominance-alerts.md",
            "https://raw.githubusercontent.com/MicrosoftDocs/ATADocs/master/ATPDocs/exfiltration-alerts.md",
            "https://raw.githubusercontent.com/MicrosoftDocs/ATADocs/master/ATPDocs/lateral-movement-alerts.md",
            "https://raw.githubusercontent.com/MicrosoftDocs/ATADocs/master/ATPDocs/reconnaissance-alerts.md",
        ]

    @staticmethod
    def set_plugin_params(parser: ArgumentParser) -> None:
        """
        Set command line arguments specific for the plugin
        :param parser: Argument parser
        """
        TechniqueBase.set_plugin_params(parser)

    def get_data_from_source(self) -> Iterable:
        """
        Gets the use-case/technique data from the source.
        :return: Iterable, yields technique, detection
        """
        for source_url in self.ATP_DOCS:
            resp = requests.get(source_url)
            body = resp.text

            # Remove comments from file, because it may contain commented detection rules.
            while "<!--" in body:
                body = body[0 : body.find("<!--")] + body[body.find("-->") + 3 :]

            regex_title = re.compile("##\s(.*\s\(external\sID\s\d{4}\))")
            regex_tech = re.compile("\((T\d{4})\)")
            regex_subtech = re.compile("(T\d{4}\.\d{3})")

            current_detection = None
            for line in body.splitlines():
                title_match = regex_title.match(line)
                if title_match or current_detection is None:
                    if title_match:
                        current_detection = title_match.group(1)
                        continue
                else:
                    if "MITRE attack technique" in line and "N/A" in line:
                        current_detection = None
                    elif "MITRE attack technique" in line:
                        tech_match = regex_tech.findall(line)
                        if tech_match:
                            for t in tech_match:
                                yield t, current_detection
                    elif "MITRE attack sub-technique" in line and "N/A" in line:
                        current_detection = None
                    elif "MITRE attack sub-technique" in line:
                        subtech_match = regex_subtech.findall(line)
                        if subtech_match:
                            for t in subtech_match:
                                yield t, current_detection
                            current_detection = None
