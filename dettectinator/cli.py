"""
Dettectinator - The Python library to your DeTT&CT YAML files.
Authors:
    Martijn Veken, Sirius Security
    Ruben Bouman, Sirius Security
License: GPL-3.0 License

Some functions and code are taken with permission from the DeTT&CT project (http://github.com/rabobank-cdc/DeTTECT).
"""

import json
import sys
import os
import glob
import importlib
import inspect
from dettectinator import (
    DettectTechniquesAdministration,
    DettectDataSourcesAdministration,
)
from plugins.base.technique import TechniqueBase
from plugins.base.datasource import DatasourceBase
from argparse import ArgumentParser, Namespace


class CommandLine:
    @staticmethod
    def _get_raw_commandline(argument_names: list) -> str:
        """
        We need to get the name from the plugin before Argument parser can do its job.
        This is because the plugin needs to be able to add its arguments to the command line
        before argument parser does its job. It's ugly, but it works :)
        :return: The name of the import plugin to load
        """
        prev = ""
        name = ""
        for item in sys.argv:
            if prev in argument_names:
                name = item
                break
            prev = item
        return name

    @staticmethod
    def _print_plugins(import_plugins: dict) -> None:
        """
        Prints the list of available data import plugins in a module
        :param import_plugins: dictionary containing the plugins
        """
        for name in import_plugins.keys():
            print(f" - {name}")

    @staticmethod
    def _get_plugins() -> dict:
        """
        Retrieves all plugins from the plugin folder
        :return: dict containing plugins and modules
        """
        import_plugins = {}
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "plugins")
        all_modules = glob.glob(f"plugins/*/datasource.py") + glob.glob(
            f"plugins/*/technique.py"
        )
        for module in all_modules:
            plugin_mod = importlib.import_module(module.replace("/", ".")[:-3])
            for name, cls in inspect.getmembers(plugin_mod, inspect.isclass):
                if ("Technique" in name or "Datasource" in name) and "Base" not in name:
                    import_plugins[name] = plugin_mod
        return import_plugins

    @staticmethod
    def _set_default_params(parser: ArgumentParser):
        """
        Set the default command line arguments
        """
        required = parser.add_argument_group("required arguments")
        parser.add_argument("-c", "--config", help="Configuration file location.")
        required.add_argument(
            "-p", "--plugin", help="Data import plugin name.", required=True
        )
        required.add_argument(
            "-a",
            "--applicable_to",
            help="Systems that the detections are applicable to (comma seperated list).",
            required=True,
        )
        parser.add_argument(
            "-d",
            "--domain",
            help="The ATT&CK domain (default = enterprise). This argument is ignored if a domain is specified in the YAML file.",
            required=False,
            choices=["enterprise", "ics", "mobile"],
        )
        parser.add_argument(
            "-i", "--input_file", help="YAML filename for input.", default=None
        )
        parser.add_argument(
            "-o", "--output_file", help="YAML filename for output.", default=None
        )
        parser.add_argument(
            "-n",
            "--name",
            help="Value for the name attribute in the YAML file.",
            default=None,
        )
        parser.add_argument(
            "-ri",
            "--re_include",
            help="Regex for detection names that should be included.",
            default=None,
        )
        parser.add_argument(
            "-re",
            "--re_exclude",
            help="Regex for detection names that should be excluded.",
            default=None,
        )
        parser.add_argument(
            "-s",
            "--stix_location",
            help="Local STIX repository location.",
            default=None,
        )

        parser.add_argument(
            "-ch",
            "--check_unused",
            action="store_true",
            help="Check unused detections.",
        )
        parser.add_argument(
            "-cl",
            "--clean_unused",
            action="store_true",
            help="Clean unused detections.",
        )

    def _get_argument_values_from_config_file(self) -> dict:
        """
        Read the command line arguments from the config file if applicable
        """
        config_file_name = self._get_raw_commandline(["-c", "--config"])
        if config_file_name:
            print(f'Reading settings from "{config_file_name}".')
            with open(config_file_name, "r") as f:
                config_file_arguments = json.load(f)
        else:
            config_file_arguments = {}
        return config_file_arguments

    @staticmethod
    def process_techniques(
        applicable_to: list, arguments: Namespace, plugin: TechniqueBase
    ) -> tuple:
        """
        Process all techiques from the source system
        """
        # Get the technique data
        rules = plugin.get_attack_techniques(applicable_to, arguments.location_prefix)
        # Convert data to yaml
        print("Generating techniques YAML file.")
        dettect = DettectTechniquesAdministration(
            arguments.input_file,
            domain=arguments.domain,
            local_stix_path=arguments.stix_location,
        )
        warnings, results = dettect.update_detections(
            rules,
            check_unused_detections=arguments.check_unused,
            clean_unused_detections=arguments.clean_unused,
        )
        return dettect, results, warnings

    @staticmethod
    def process_datasource(
        applicable_to: list, arguments: Namespace, plugin: DatasourceBase
    ) -> tuple:
        """
        Process all techiques from the source system
        """
        # Get the technique data
        datasources = plugin.get_attack_datasources(applicable_to)
        # Convert data to yaml
        print("Generating datasources YAML file.")
        dettect = DettectDataSourcesAdministration(
            arguments.input_file,
            domain=arguments.domain,
            local_stix_path=arguments.stix_location,
        )
        warnings, results = dettect.update_data_sources(
            datasources,
            check_unused_data_sources=arguments.check_unused,
            clean_unused_data_sources=arguments.clean_unused,
        )
        return dettect, results, warnings

    def start(self):

        # Load default argument values from the config file
        config_file_arguments = self._get_argument_values_from_config_file()

        # Retrieve all available plugins
        plugins = self._get_plugins()

        # Get the plugin name from the arguments
        plugin_name = config_file_arguments.get(
            "plugin", self._get_raw_commandline(["-p", "--plugin"])
        )

        if plugin_name:
            # Get the plugin class if it exists
            if plugin_name in plugins.keys():
                plugin_class = getattr(plugins[plugin_name], plugin_name)
                print(f'Plugin "{plugin_name}" has been found.')
            else:
                print(
                    f'data import plugin "{plugin_name}" does not exist. Valid plugins:'
                )
                self._print_plugins(plugins)
                sys.exit()

            # Add the default command line params
            parser = ArgumentParser(
                add_help=True,
                conflict_handler="error",
            )
            self._set_default_params(parser)

            # Add the parameters from the plugin
            plugin_group = parser.add_argument_group(plugin_name)
            plugin_class.set_plugin_params(plugin_group)

            # Set the default values from the config file
            # Default and required don't work together, so set required to False
            parser.set_defaults(**config_file_arguments)
            for action in parser._actions:
                if action.dest in config_file_arguments.keys():
                    action.required = False

            # Evaluate command line arguments
            arguments = parser.parse_args()
            applicable_to = [at.strip() for at in arguments.applicable_to.split(",")]
            output_file = arguments.output_file or arguments.input_file

            # Read the data from the source
            print(f'Using "{plugin_name}" to collect data.')
            plugin = plugin_class(vars(arguments))

            if plugin_name.startswith("Technique"):
                dettect, results, warnings = self.process_techniques(
                    applicable_to, arguments, plugin
                )
            else:
                dettect, results, warnings = self.process_datasource(
                    applicable_to, arguments, plugin
                )

            if arguments.name:
                dettect.set_name(arguments.name)

            dettect.save_yaml_file(output_file)
            print(f"DeTT&CT YAML file written: {dettect.get_filename()}")

            output = warnings + results
            if len(output) > 0:
                print("\nPlease review the following items:")
                print(" - " + "\n - ".join(output))
        else:
            print('Please specify a valid data import plugin using the "-p" argument:')
            self._print_plugins(plugins)
