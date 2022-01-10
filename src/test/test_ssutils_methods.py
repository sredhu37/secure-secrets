#############################################
# Variables naming convention               #
# o     => object                           #
# s     => string                           #
# by    => bytes                            #
# l     => list                             #
# d     => dictionary                       #
#############################################

import sys
sys.path.append('../main')      # To import ssutils

import unittest
from cryptography.fernet import Fernet
import ssutils

s_fernet_key = Fernet.generate_key()
o_fernet_key = Fernet(s_fernet_key)


class TestSsUtilsMethods(unittest.TestCase):
  def test_encrypt_and_decrypt_text(self):
    s_text_to_encrypt = "Testing the ssutils.py encrypt and decrypt methods"
    s_encrypted_text = ssutils.encrypt_text(o_fernet_key, s_text_to_encrypt)
    s_decrypted_text = ssutils.decrypt_text(o_fernet_key, s_encrypted_text)

    self.assertEqual(s_text_to_encrypt, s_decrypted_text)


if __name__ == '__main__':
  unittest.main()
