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
import os


class TechniqueSigmaRules(TechniqueBase):
    """
    Import data from a folder with Sigma rules.
    """

    def __init__(self, parameters: dict) -> None:
        super().__init__(parameters)
        if "folder" not in self._parameters:
            raise Exception('DetectionSigmaRules: "folder" parameter is required.')

    @staticmethod
    def set_plugin_params(parser: ArgumentParser) -> None:
        """
        Set command line arguments specific for the plugin
        :param parser: Argument parser
        """
        TechniqueBase.set_plugin_params(parser)

        parser.add_argument(
            "--folder",
            help="Path of the folder with Sigma rules to import",
            required=True,
        )

    def get_data_from_source(self) -> Iterable:
        """
        Gets the use-case/technique data from the source.
        :return: Iterable, yields technique, detection
        """
        folder = self._parameters["folder"]

        if not os.path.isdir(folder):
            raise Exception(f"Folder does not exist: {folder}")

        from ruamel.yaml import YAML

        print(f'Reading data from "{folder}"')

        for root, _, files in os.walk(folder):
            for file in files:
                if file.endswith(".yaml") or file.endswith(".yml"):
                    filename = os.path.join(root, file)
                    yaml = YAML()
                    try:
                        with open(filename, "r") as yaml_file:
                            yaml_content = yaml.load(yaml_file)
                    except Exception as e:
                        raise Exception(
                            f'Failed loading YAML file "{filename}". Error: {str(e)}'
                        ) from e

                    if "tags" in yaml_content.keys():
                        for tag in yaml_content["tags"]:
                            if tag.startswith("attack.t"):
                                yield tag[7:].upper(), yaml_content["title"]
