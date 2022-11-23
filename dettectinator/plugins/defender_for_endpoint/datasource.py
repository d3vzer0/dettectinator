"""
Dettectinator - The Python library to your DeTT&CT YAML files.
Authors:
    Martijn Veken, Sirius Security
    Ruben Bouman, Sirius Security
License: GPL-3.0 License
"""

from argparse import ArgumentParser
from collections.abc import Iterable
from plugins.base.datasource import DatasourceOssemBase
import json


class DatasourceDefenderEndpoints(DatasourceOssemBase):
    """
    Base class for importing use-case/technique data
    """

    __category__ = "Datasource"

    def __init__(self, parameters: dict) -> None:
        super().__init__(parameters)
        self._log_source = "Microsoft Defender for Endpoint"

    @staticmethod
    def set_plugin_params(parser: ArgumentParser) -> None:
        """
        Set command line arguments specific for the plugin
        :param parser: Argument parser
        """
        pass

    def get_data_from_source(self) -> Iterable:
        """
        Gets the datasource/product data from the source.
        :return: Iterable, yields technique, detection
        """
        ossem_data = self._get_ossem_data()

        for record in ossem_data:
            action_types = json.loads(record["Filter in Log"].replace("'", '"'))
            if len(action_types) > 0:
                for action_type in action_types:
                    yield str(
                        record["Component"]
                    ).title(), f'{record ["Event Name"]}: {action_type["ActionType"]}'
            else:
                yield str(record["Component"]).title(), record["Event Name"]
