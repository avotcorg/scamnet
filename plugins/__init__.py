import importlib
import os

def load_plugins():
    plugins = {}
    path = os.path.dirname(__file__)
    for file in os.listdir(path):
        if file.endswith(".py") and file not in ["__init__.py"]:
            name = file[:-3]
            module = importlib.import_module(f"plugins.{name}")
            plugins[name] = module
    return plugins
