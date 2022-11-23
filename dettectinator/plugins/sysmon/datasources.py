"""
Dettectinator - The Python library to your DeTT&CT YAML files.
Authors:
    Martijn Veken, Sirius Security
    Ruben Bouman, Sirius Security
License: GPL-3.0 License
"""


from argparse import ArgumentParser
from collections.abc import Iterable
from plugins.base.datasources import DatasourceOssemBase
from xml.etree.ElementTree import Element
import xml.etree.ElementTree as ElementTree



class DatasourceWindowsSysmon(DatasourceOssemBase):
    """
    Base class for importing use-case/technique data
    """

    def __init__(self, parameters: dict) -> None:
        super().__init__(parameters)

        if 'sysmon_config' not in self._parameters:
            raise Exception('DatasourceWindowsSysmon: "sysmon_config" parameter is required.')

        self._sysmon_config = parameters['sysmon_config']
        self._log_source = 'Microsoft-Windows-Sysmon'

    @staticmethod
    def set_plugin_params(parser: ArgumentParser) -> None:
        """
        Set command line arguments specific for the plugin
        :param parser: Argument parser
        """
        parser.add_argument('--sysmon_config', help='Path of the Sysmon config file.', required=True)

    def get_data_from_source(self) -> Iterable:
        """
        Gets the datasource/product data from the source.
        :return: Iterable, yields technique, detection
        """
        ossem_data = self._get_ossem_data()
        sysmon_config = self._get_sysmon_config()

        for record in ossem_data:
            config_items = sysmon_config.findall(f'.//{record["Audit Category"]}')

            # If the is an event type with an onmatch == include attribute without child items this means
            # that nothing is being logged for this event type
            for config_item in config_items:
                if config_item.attrib['onmatch'] == "include" and len(config_item.getchildren()) == 0:
                    continue

            yield str(record['Component']).title(), f'{record["EventID"]}: {record["Event Name"]}'

    def _get_sysmon_config(self) -> Element:
        """
        Gets the Sysmon config from the filesystem
        """
        tree = ElementTree.parse(self._sysmon_config)
        root = tree.getroot()
        return root