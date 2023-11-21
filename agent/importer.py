"""Dynamic importer to enable registry pattern."""
import logging
import sys
import traceback
import os
import pkgutil
from typing import Callable

logger = logging.getLogger(__name__)


def importer_for(path: str, prefix: str) -> Callable[[], None]:
    """
    Creates a function for importing all Python files in a specified folder and adding them as attributes
    to a given module.
    Args:
        path (str): the path to the folder containing the Python files to import
        prefix (str): the prefix to use when adding the imported files as attributes to the module
    Returns:
        A function that can be called to perform the import and attribute assignment. The function takes two
        optional arguments:
        - file_path (str): the path to the folder containing the Python files to import (default is `path`)
        - stop_on_error (bool): whether to stop execution if an error occurs during import (default is `True`)
    """

    def import_all(path: str = path, stop_on_error: bool = True) -> None:
        """
        Imports all Python files in a specified folder and adds them as attributes to a given module.
        Args:
            file_path (str): the path to the folder containing the Python files to import
             (default is the value passed to `importer_for`)
            stop_on_error (bool): whether to stop execution if an error occurs during import (default is `True`)
        """
        folder = os.path.dirname(path)
        module = sys.modules[prefix]
        for importer, name, _ in pkgutil.iter_modules([folder]):
            absname = prefix + "." + name
            if absname in sys.modules:
                continue
            loader = importer.find_module(absname)  # type: ignore[call-arg]
            try:
                if loader is not None:
                    submod = loader.load_module(absname)
            except ImportError as e:
                if stop_on_error:
                    raise
                # This is for debugging to print the full trace and pinpoint to source of the exception.
                traceback.print_exc()
                logger.warning("Cannot load REbus plugin [%s]. Root cause: %s", name, e)
            else:
                setattr(module, name, submod)

    return import_all
