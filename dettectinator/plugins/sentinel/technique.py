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
import sys
import requests
import urllib3

try:
    # When dettectinator is installed as python library
    from dettectinator.plugins.support.authentication import Azure
except ModuleNotFoundError:
    # When dettectinator is not installed as python library
    sys.path.append(os.path.dirname(os.path.abspath(__file__).replace('plugins', '')))
    from plugins.support.authentication import Azure


# Disable SSL certificate warnings for dev purposes:
urllib3.disable_warnings()



class TechniqueAzureAuthBase(TechniqueBase):
    """
    Base class for import plugins that authenticate against Azure AD
    """

    def __init__(self, parameters: dict) -> None:
        super().__init__(parameters)

        if 'app_id' not in self._parameters:
            raise Exception(f'{self.__class__.__name__}: "app_id" parameter is required.')

        if 'tenant_id' not in self._parameters:
            raise Exception(f'{self.__class__.__name__}: "tenant_id" parameter is required.')

        self._app_id = self._parameters['app_id']
        self._tenant_id = self._parameters['tenant_id']
        self._secret = self._parameters.get('secret', None)

    @staticmethod
    def set_plugin_params(parser: ArgumentParser) -> None:
        """
        Set command line arguments specific for the plugin
        :param parser: Argument parser
        """
        TechniqueBase.set_plugin_params(parser)

        parser.add_argument('--app_id', help='Azure application id', required=True)
        parser.add_argument('--tenant_id', help='Azure tenant id', required=True)
        parser.add_argument('--secret', help='Azure client secret')

    def get_data_from_source(self) -> Iterable:
        """
         Gets the use-case/technique data from the source.
         :return: Iterable, yields technique, detection
         """
        raise NotImplementedError()

    def _connect_to_azure(self, endpoint: str) -> str:
        if self._secret:
            return Azure.connect_client_secret(self._app_id, self._tenant_id, endpoint, self._secret)
        else:
            return Azure.connect_device_flow(self._app_id, self._tenant_id, endpoint)


class TechniqueSentinelAlertRules(TechniqueAzureAuthBase):
    """
    Import Analytics Rules from the Sentinel API
    """

    def __init__(self, parameters: dict) -> None:
        super().__init__(parameters)

        if 'subscription_id' not in self._parameters:
            raise Exception('DetectionSentinelAlertRules: "subscription_id" parameter is required.')

        if 'resource_group' not in self._parameters:
            raise Exception('DetectionSentinelAlertRules: "resource_group" parameter is required.')

        if 'workspace' not in self._parameters:
            raise Exception('DetectionSentinelAlertRules: "workspace" parameter is required.')

        self._subscription_id = self._parameters['subscription_id']
        self._resource_group = self._parameters['resource_group']
        self._workspace = self._parameters['workspace']
        self._endpoint = 'https://management.azure.com'

    @staticmethod
    def set_plugin_params(parser: ArgumentParser) -> None:
        """
        Set command line arguments specific for the plugin
        :param parser: Argument parser
        """
        TechniqueAzureAuthBase.set_plugin_params(parser)

        parser.add_argument('--subscription_id', help='Azure subscription id for Sentinel', required=True)
        parser.add_argument('--resource_group', help='Azure resource group for Sentinel', required=True)
        parser.add_argument('--workspace', help='Azure workspace for Sentinel', required=True)

    def get_data_from_source(self) -> Iterable:
        """
         Gets the use-case/technique data from the source.
         :return: Iterable, yields technique, detection
         """
        access_token = self._connect_to_azure(self._endpoint)
        sentinel_data = self._get_sentinel_data(access_token)

        for record in sentinel_data:
            properties = record['properties']

            if 'techniques' in properties and properties['techniques']:
                for technique in properties['techniques']:
                    use_case = properties['displayName']
                    yield technique, use_case

    def _get_sentinel_data(self, access_token: str) -> list:
        """
        Execute a query on Advanced Hunting to retrieve the use-case/technique data
        :param access_token: JWT token to execute the request on the backend
        :return: Dictionary containing the results
        """
        url = f'https://management.azure.com/subscriptions/{self._subscription_id}/resourceGroups/{self._resource_group}/' + \
              f'providers/Microsoft.OperationalInsights/workspaces/{self._workspace}/providers/Microsoft.SecurityInsights/' + \
              'alertRules?api-version=2022-07-01-preview'

        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization': 'Bearer ' + access_token
        }
        response = requests.get(url=url, headers=headers)

        if response.status_code != requests.codes['ok']:
            # Raise an exception to handle hitting API limits
            if response.status_code == requests.codes['too_many_requests']:
                raise ConnectionRefusedError('DetectionSentinelAlerts: You have likely hit the API limit. ')
            response.raise_for_status()

        json_response = response.json()
        result = json_response['value'] if 'value' in json_response else []

        return result


