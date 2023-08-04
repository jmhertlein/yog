import unittest
import yog.host.necronomicon as n
import yaml


class NecronomiconTest(unittest.TestCase):
    def test_pipx_load(self):
        pipx: n.PipXSection = n.PipXSection.from_parsed(yaml.safe_load("""
extra_indices:
  - https://pyrepo.hert/
packages:
  - name: paramiko
    version: 3.3.1
"""))
        self.assertEqual("3.3.1", pipx.packages[0].version)
        self.assertEqual("paramiko", pipx.packages[0].name)
        self.assertEqual("https://pyrepo.hert/", pipx.extra_indices[0])


if __name__ == '__main__':
    unittest.main()
