import unittest
from unittest.mock import patch, MagicMock
from server import list_vms, manage_power, get_vboxmanage_path

class TestVirtualBoxMCP(unittest.TestCase):

    @patch('server.shutil.which')
    @patch('server.os.path.exists')
    def test_get_vboxmanage_path_found_in_path(self, mock_exists, mock_which):
        mock_which.return_value = "/usr/bin/VBoxManage"
        path = get_vboxmanage_path()
        self.assertEqual(path, "/usr/bin/VBoxManage")

    @patch('server.subprocess.run')
    @patch('server.get_vboxmanage_path')
    def test_list_vms_success(self, mock_get_path, mock_run):
        mock_get_path.return_value = "VBoxManage"
        
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.stdout = '"TestVM" {1234-5678}'
        mock_run.return_value = mock_process
        
        result = list_vms()
        self.assertIn("TestVM", result)
        self.assertIn("RUNNING", result)

    def test_manage_power_invalid_action(self):
        result = manage_power("TestVM", "destroy-everything")
        self.assertIn("Error: Invalid action", result)

    @patch('server.get_vboxmanage_path')
    def test_list_vms_exception_handling(self, mock_get_path):
        mock_get_path.side_effect = Exception("Forced failure")
        result = list_vms()
        self.assertIn("Error: Failed to list VMs", result)

if __name__ == '__main__':
    unittest.main()