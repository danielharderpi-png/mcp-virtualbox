import unittest
from unittest.mock import patch, MagicMock
from server import (
    list_vms, 
    manage_power, 
    get_vm_info, 
    manage_snapshot, 
    execute_guest_command, 
    get_vboxmanage_path
)

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

    def test_manage_power_invalid_action(self):
        result = manage_power("TestVM", "destroy")
        self.assertIn("Error: Invalid action", result)

    @patch('server.run_vbox_cmd')
    def test_get_vm_info(self, mock_run):
        mock_run.return_value = "Memory size: 2048MB"
        result = get_vm_info("TestVM")
        self.assertIn("2048MB", result)

    @patch('server.run_vbox_cmd')
    def test_manage_snapshot(self, mock_run):
        mock_run.return_value = "Snapshot taken"
        result = manage_snapshot("TestVM", "take", "Backup1")
        self.assertIn("Successfully", result)

    @patch('server.run_vbox_cmd')
    def test_execute_guest_command(self, mock_run):
        mock_run.return_value = "root"
        result = execute_guest_command("TestVM", "user", "pass", "whoami")
        self.assertIn("root", result)

if __name__ == '__main__':
    unittest.main()