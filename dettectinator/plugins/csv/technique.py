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


class TechniqueCsv(TechniqueBase):
    """
    Import data from a CSV file, formatted TechniqueId,UseCase
    """

    def __init__(self, parameters: dict) -> None:
        super().__init__(parameters)
        if "file" not in self._parameters:
            raise Exception('TechniqueCsv: "file" parameter is required.')

    @staticmethod
    def set_plugin_params(parser: ArgumentParser) -> None:
        """
        Set command line arguments specific for the plugin
        :param parser: Argument parser
        """
        TechniqueBase.set_plugin_params(parser)

        parser.add_argument(
            "--file", help="Path of the csv file to import", required=True
        )

    def get_data_from_source(self) -> Iterable:
        """
        Gets the use-case/technique data from the source.
        :return: Iterable, yields technique, detection
        """
        file = self._parameters["file"]
        print(f'Reading data from "{file}"')

        with open(file) as f:
            lines = f.readlines()

        for detection in lines:
            parts = detection.split(",")
            technique = parts[0].strip()
            use_case = parts[1].strip()
            yield technique, use_case
