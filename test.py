# Copyright (c) 2022 The Zcash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

import unittest

def test():
    loader = unittest.TestLoader()
    suite = loader.discover('.', pattern='*.py')
    runner = unittest.TextTestRunner()
    runner.run(suite)
