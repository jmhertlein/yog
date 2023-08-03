import unittest
from yog.host.pipx import get_packages_from_pipx_json

json_sample = """
{
    "pipx_spec_version": "0.1",
    "venvs": {
        "yog": {
            "metadata": {
                "injected_packages": {},
                "main_package": {
                    "app_paths": [
                        {
                            "__Path__": "/home/josh/.local/pipx/venvs/yog/bin/yog",
                            "__type__": "Path"
                        },
                        {
                            "__Path__": "/home/josh/.local/pipx/venvs/yog/bin/yog-pki",
                            "__type__": "Path"
                        },
                        {
                            "__Path__": "/home/josh/.local/pipx/venvs/yog/bin/yog-repo",
                            "__type__": "Path"
                        }
                    ],
                    "app_paths_of_dependencies": {
                        "charset-normalizer": [
                            {
                                "__Path__": "/home/josh/.local/pipx/venvs/yog/bin/normalizer",
                                "__type__": "Path"
                            }
                        ],
                        "websocket-client": [
                            {
                                "__Path__": "/home/josh/.local/pipx/venvs/yog/bin/wsdump",
                                "__type__": "Path"
                            }
                        ]
                    },
                    "apps": [
                        "yog",
                        "yog-pki",
                        "yog-repo"
                    ],
                    "apps_of_dependencies": [
                        "normalizer",
                        "wsdump"
                    ],
                    "include_apps": true,
                    "include_dependencies": false,
                    "package": "yog",
                    "package_or_url": "yog",
                    "package_version": "2.2.5",
                    "pip_args": [],
                    "suffix": ""
                },
                "pipx_metadata_version": "0.2",
                "python_version": "Python 3.11.2",
                "venv_args": []
            }
        }
    }
}
"""


class TestPipX(unittest.TestCase):
    def test_cmd_parse(self):
        pkgs = get_packages_from_pipx_json(json_sample)
        self.assertEqual("2.2.5", pkgs["yog"])


if __name__ == '__main__':
    unittest.main()
