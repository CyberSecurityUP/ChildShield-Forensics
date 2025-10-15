import importlib.util
import os
from types import ModuleType

PLUGIN_DIR = os.path.join(os.getcwd(), "plugins")

def discover_plugins():
    plugins = []
    if not os.path.isdir(PLUGIN_DIR):
        return plugins
    for fn in os.listdir(PLUGIN_DIR):
        if fn.endswith(".py") and not fn.startswith("_"):
            plugins.append(os.path.join(PLUGIN_DIR, fn))
    return plugins

def load_plugin(path):
    name = os.path.splitext(os.path.basename(path))[0]
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def run_plugins_on_path(path, context):
    results = []
    for p in discover_plugins():
        try:
            mod = load_plugin(p)
            if hasattr(mod, "scan"):
                res = mod.scan(path, context)
                results.append({"plugin": os.path.basename(p), "result": res})
        except Exception as e:
            results.append({"plugin": os.path.basename(p), "error": str(e)})
    return results
