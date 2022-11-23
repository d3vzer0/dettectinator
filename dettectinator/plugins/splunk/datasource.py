"""
Dettectinator - The Python library to your DeTT&CT YAML files.
Authors:
    Martijn Veken, Sirius Security
    Ruben Bouman, Sirius Security
License: GPL-3.0 License
"""


from plugins.base.datasource import DatasourceOssemBase
from argparse import ArgumentParser
from collections.abc import Iterable


class DatasourceSplunkSourcetypes(DatasourceOssemBase):
    """
    Base class for importing use-case/technique data
    """

    __category__ = 'Datasource'

    def __init__(self, parameters: dict) -> None:
        super().__init__(parameters)

        is_token_auth = self._parameters.get('token')
        if not is_token_auth and not 'username' in self._parameters and not 'password' in self._parameters:
            raise Exception(f'{self.__class__.__name__}: "No token or username/passsword provided')

        self._log_source = 'Splunk Sourcetypes'

    @staticmethod
    def set_plugin_params(parser: ArgumentParser) -> None:
        """
        Set command line arguments specific for the plugin
        :param parser: Argument parser
        """
        parser.add_argument('--uri', help='Splunk API uri', required=True)
        parser.add_argument('--username', help='Username of Splunk user (if applicable)', required=False)
        parser.add_argument('--password', help='Password of Splunk user (if applicable)', required=False)
        parser.add_argument('--token', help='Token of Splunk user (if applicable).', required=False)

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
