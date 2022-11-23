
"""
Dettectinator - The Python library to your DeTT&CT YAML files.
Authors:
    Martijn Veken, Sirius Security
    Ruben Bouman, Sirius Security
License: GPL-3.0 License
"""


from argparse import ArgumentParser
from collections.abc import Iterable
import re


class DatasourceBase:
    """
    Base class for importing datasource/product data
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
        raise NotImplementedError()

    def get_attack_datasources(self, applicable_to: list) -> dict:
        """
        Retrieves datasource/product data from a data source
        :param applicable_to: Systems that the datasources are applicable to.
        :return: Dictionary, example: {"User Account Creation":[{"applicable_to":["test"],"available_for_data_analytics":true,"products":["DeviceEvents: UserAccountCreated"]}]}
        """

        data_sources = {}

        for datasource, product in self.get_data_from_source():
            # Exclude all products that match the exclude-pattern
            if self._re_exclude and not re.match(self._re_exclude, product) is None:
                continue

            # Include all products that match the include-pattern
            if self._re_include and re.match(self._re_include, product) is None:
                continue

            if datasource not in data_sources.keys():
                record = {'applicable_to': applicable_to, 'available_for_data_analytics': True, 'products': []}
                data_sources[datasource] = [record]
            else:
                record = data_sources[datasource][0]

            if product not in record['products']:
                record['products'].append(product)

        return data_sources

    def get_data_from_source(self) -> Iterable:
        """
        Gets the datasource/product data from the source.
        :return: Iterable, yields technique, detection
        """
        raise NotImplementedError()


class DatasourceOssemBase(DatasourceBase):
    """
    Base class for importing datasource/product data that is based on OSSEM data
    For information about OSSEM see: https://github.com/OTRF/OSSEM-DM
    """

    def __init__(self, parameters: dict) -> None:
        super().__init__(parameters)
        self._log_source = None

    @staticmethod
    def set_plugin_params(parser: ArgumentParser) -> None:
        """
        Set command line arguments specific for the plugin
        :param parser: Argument parser
        """
        raise NotImplementedError()

    def get_data_from_source(self) -> Iterable:
        """
        Gets the datasource/product data from the source.
        :return: Iterable, yields technique, detection
        """
        raise NotImplementedError()

    def _get_ossem_data(self):
        """
        Retrieves data from the OSSEM ATT&CK mapping
        """
        import pandas

        url = 'https://raw.githubusercontent.com/OTRF/OSSEM-DM/main/use-cases/mitre_attack/attack_events_mapping.csv'
        data = pandas.read_csv(url)
        data.where(data['Log Source'] == self._log_source, inplace=True)
        data.dropna(how='all', inplace=True)
        select = data[['Data Source', 'Component', 'EventID', 'Event Name', 'Filter in Log', 'Audit Category']]
        dict_result = select.to_dict(orient="records")
        return dict_result
