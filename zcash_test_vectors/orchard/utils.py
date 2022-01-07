#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

from .pallas import Fp, Scalar
from ..utils import leos2ip

#
# Utilities
#

def to_scalar(buf):
    return Scalar(leos2ip(buf))

def to_base(buf):
    return Fp(leos2ip(buf))
