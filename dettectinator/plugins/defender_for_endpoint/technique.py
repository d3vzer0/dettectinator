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
import re
import requests
import urllib3

try:
    # When dettectinator is installed as python library
    from dettectinator.plugins.support.authentication import Azure, Tanium
except ModuleNotFoundError:
    # When dettectinator is not installed as python library
    sys.path.append(os.path.dirname(os.path.abspath(__file__).replace('plugins', '')))
    from plugins.support.authentication import Azure, Tanium


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


class TechniqueDefenderAlerts(TechniqueAzureAuthBase):
    """
    Import alerts and techniques from the Microsft Defender API.
    """
    def __init__(self, parameters: dict) -> None:
        super().__init__(parameters)

        self._endpoint = 'https://api.security.microsoft.com'

    def get_data_from_source(self) -> Iterable:
        """
        Gets the use-case/technique data from the source.
        :return: Iterable, yields technique, detection
        """
        access_token = self._connect_to_azure(self._endpoint)
        defender_data = self._get_defender_data(access_token)

        for record in defender_data:
            technique = record['TechniqueId']
            use_case = record['Title'].strip()
            yield technique, use_case

    @staticmethod
    def _get_defender_data(access_token: str) -> dict:
        """
        Execute a query on Advanced Hunting to retrieve the use-case/technique data
        :param access_token: JWT token to execute the request on the backend
        :return: Dictionary containing the results
        """
        query = '''
        AlertInfo
        | mv-expand todynamic(AttackTechniques)
        | extend TechniqueId = extract(@'\((T.*)\)', 1, tostring(AttackTechniques))
        | where isnotempty(TechniqueId)
        | distinct TechniqueId, Title
        | order by TechniqueId
        '''

        url = 'https://api.security.microsoft.com/api/advancedhunting/run'
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization': 'Bearer ' + access_token
        }

        data = json.dumps({'Query': query}).encode('utf-8')

        response = requests.post(url=url, headers=headers, data=data)

        if response.status_code != requests.codes['ok']:
            # Raise an exception to handle hitting API limits
            if response.status_code == requests.codes['too_many_requests']:
                raise ConnectionRefusedError('DetectionDefenderAlerts: You have likely hit the API limit. ')
            response.raise_for_status()

        json_response = response.json()
        result = json_response['Results'] if 'Results' in json_response else {}

        return result