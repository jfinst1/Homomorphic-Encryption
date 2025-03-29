import unittest
from utils.error_handling import ErrorHandler

class TestErrorHandler(unittest.TestCase):

    def setUp(self):
        self.error_handler = ErrorHandler()

    def test_handle_error(self):
        with self.assertRaises(ValueError):
            self.error_handler.handle_error(ValueError("Test Error"))

    def test_retry_operation(self):
        def fail_operation():
            raise ValueError("Test Error")
        
        with self.assertRaises(ValueError):
            self.error_handler.retry_operation(fail_operation, retries=2)

    def test_classify_error(self):
        self.assertEqual(self.error_handler.classify_error(ValueError()), "Recoverable")
        self.assertEqual(self.error_handler.classify_error(TypeError()), "Non-recoverable")
        self.assertEqual(self.error_handler.classify_error(Exception()), "Unknown")

    def test_add_and_verify_crc32(self):
        data = b"Test data"
        data_with_crc = self.error_handler.add_crc32(data)
        verified_data = self.error_handler.verify_crc32(data_with_crc)
        self.assertEqual(verified_data, data)

    def test_context_aware_handling(self):
        try:
            raise ValueError("Test Recoverable Error")
        except Exception as e:
            self.error_handler.context_aware_handling("Test Context", e)

if __name__ == '__main__':
    unittest.main()