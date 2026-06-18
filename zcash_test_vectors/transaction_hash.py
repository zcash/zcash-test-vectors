#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

from hashlib import blake2b
import struct

from .transaction import (
    MAX_MONEY,
    Script,
)
from .rand import Rand
from .zip_0143 import (
    getHashOutputs,
    getHashPrevouts,
    getHashSequence,
    SIGHASH_ALL,
    SIGHASH_ANYONECANPAY,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
)


# Transparent

def transparent_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxIdTranspaHash')

    if len(tx.vin) + len(tx.vout) > 0:
        digest.update(getHashPrevouts(tx, b'ZTxIdPrevoutHash'))
        digest.update(getHashSequence(tx, b'ZTxIdSequencHash'))
        digest.update(getHashOutputs(tx, b'ZTxIdOutputsHash'))

    return digest.digest()

def transparent_scripts_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxAuthTransHash')
    for x in tx.vin:
        digest.update(bytes(x.scriptSig))
    return digest.digest()

def sapling_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxIdSaplingHash')

    if len(tx.vSpendsSapling) + len(tx.vOutputsSapling) > 0:
        digest.update(sapling_spends_digest(tx))
        digest.update(sapling_outputs_digest(tx))
        digest.update(struct.pack('<Q', tx.valueBalanceSapling))

    return digest.digest()

def sapling_auth_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxAuthSapliHash')

    if len(tx.vSpendsSapling) + len(tx.vOutputsSapling) > 0:
        for desc in tx.vSpendsSapling:
            digest.update(bytes(desc.proof))
        for desc in tx.vSpendsSapling:
            digest.update(bytes(desc.spendAuthSig))
        for desc in tx.vOutputsSapling:
            digest.update(bytes(desc.proof))
        digest.update(bytes(tx.bindingSigSapling))

    return digest.digest()

# - Spends

def sapling_spends_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxIdSSpendsHash')

    if len(tx.vSpendsSapling) > 0:
        digest.update(sapling_spends_compact_digest(tx))
        digest.update(sapling_spends_noncompact_digest(tx))

    return digest.digest()

def sapling_spends_compact_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxIdSSpendCHash')
    for desc in tx.vSpendsSapling:
        digest.update(desc.nullifier)
    return digest.digest()

def sapling_spends_noncompact_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxIdSSpendNHash')
    for desc in tx.vSpendsSapling:
        digest.update(bytes(desc.cv))
        digest.update(bytes(desc.anchor))
        digest.update(bytes(desc.rk))
    return digest.digest()

# - Outputs

def sapling_outputs_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxIdSOutputHash')

    if len(tx.vOutputsSapling) > 0:
        digest.update(sapling_outputs_compact_digest(tx))
        digest.update(sapling_outputs_memos_digest(tx))
        digest.update(sapling_outputs_noncompact_digest(tx))

    return digest.digest()

def sapling_outputs_compact_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxIdSOutC__Hash')
    for desc in tx.vOutputsSapling:
        digest.update(bytes(desc.cmu))
        digest.update(bytes(desc.ephemeralKey))
        digest.update(desc.encCiphertext[:52])
    return digest.digest()

def sapling_outputs_memos_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxIdSOutM__Hash')
    for desc in tx.vOutputsSapling:
        digest.update(desc.encCiphertext[52:564])
    return digest.digest()

def sapling_outputs_noncompact_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxIdSOutN__Hash')
    for desc in tx.vOutputsSapling:
        digest.update(bytes(desc.cv))
        digest.update(desc.encCiphertext[564:])
        digest.update(desc.outCipherText)
    return digest.digest()

# Orchard-shaped bundles

ORCHARD_PERSONALIZATIONS = {
    'bundle': b'ZTxIdOrchardHash',
    'actions_compact': b'ZTxIdOrcActCHash',
    'actions_memos': b'ZTxIdOrcActMHash',
    'actions_noncompact': b'ZTxIdOrcActNHash',
    'auth': b'ZTxAuthOrchaHash',
}

BUNDLE_FORMAT_PRE_NU6_3 = 'pre_nu6_3'


def encode_orchard_flags(flags, bundle_format):
    if bundle_format == BUNDLE_FORMAT_PRE_NU6_3:
        assert flags & ~0b011 == 0
    else:
        raise ValueError('Unknown Orchard bundle format: %s' % bundle_format)
    return flags


def orchard_bundle_digest(
        actions,
        flags,
        value_balance,
        anchor,
        personalizations,
        bundle_format,
        include_anchor):
    digest = blake2b(digest_size=32, person=personalizations['bundle'])

    if len(actions) > 0:
        digest.update(orchard_actions_compact_digest(actions, personalizations))
        digest.update(orchard_actions_memos_digest(actions, personalizations))
        digest.update(orchard_actions_noncompact_digest(actions, personalizations))
        digest.update(struct.pack('<B', encode_orchard_flags(flags, bundle_format)))
        digest.update(struct.pack('<q', value_balance))
        if include_anchor:
            digest.update(bytes(anchor))

    return digest.digest()


def orchard_bundle_auth_digest(
        actions,
        anchor,
        proofs,
        binding_sig,
        personalizations,
        include_anchor):
    digest = blake2b(digest_size=32, person=personalizations['auth'])

    if len(actions) > 0:
        digest.update(proofs)
        for desc in actions:
            digest.update(bytes(desc.spendAuthSig))
        digest.update(bytes(binding_sig))
        if include_anchor:
            digest.update(bytes(anchor))

    return digest.digest()

def orchard_digest(tx):
    return orchard_bundle_digest(
        tx.vActionsOrchard,
        getattr(tx, 'flagsOrchard', 0),
        tx.valueBalanceOrchard,
        getattr(tx, 'anchorOrchard', b''),
        ORCHARD_PERSONALIZATIONS,
        BUNDLE_FORMAT_PRE_NU6_3,
        True,
    )

def orchard_auth_digest(tx):
    return orchard_bundle_auth_digest(
        tx.vActionsOrchard,
        getattr(tx, 'anchorOrchard', b''),
        getattr(tx, 'proofsOrchard', b''),
        getattr(tx, 'bindingSigOrchard', b''),
        ORCHARD_PERSONALIZATIONS,
        False,
    )

# - Actions

def orchard_actions_compact_digest(actions, personalizations=ORCHARD_PERSONALIZATIONS):
    digest = blake2b(digest_size=32, person=personalizations['actions_compact'])
    for desc in actions:
        digest.update(bytes(desc.nullifier))
        digest.update(bytes(desc.cmx))
        digest.update(bytes(desc.ephemeralKey))
        digest.update(desc.encCiphertext[:52])
    return digest.digest()

def orchard_actions_memos_digest(actions, personalizations=ORCHARD_PERSONALIZATIONS):
    digest = blake2b(digest_size=32, person=personalizations['actions_memos'])
    for desc in actions:
        digest.update(desc.encCiphertext[52:564])
    return digest.digest()

def orchard_actions_noncompact_digest(actions, personalizations=ORCHARD_PERSONALIZATIONS):
    digest = blake2b(digest_size=32, person=personalizations['actions_noncompact'])
    for desc in actions:
        digest.update(bytes(desc.cv))
        digest.update(bytes(desc.rk))
        digest.update(desc.encCiphertext[564:])
        digest.update(desc.outCiphertext)
    return digest.digest()

# Transaction

def header_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxIdHeadersHash')

    digest.update(struct.pack('<I', tx.version_bytes()))
    digest.update(struct.pack('<I', tx.nVersionGroupId))
    digest.update(struct.pack('<I', tx.nConsensusBranchId))
    digest.update(struct.pack('<I', tx.nLockTime))
    digest.update(struct.pack('<I', tx.nExpiryHeight))
    if hasattr(tx, 'zip233Amount'):
        digest.update(struct.pack('<Q', tx.zip233Amount))

    return digest.digest()

def txid_digest(tx):
    digest = blake2b(
        digest_size=32,
        person=b'ZcashTxHash_' + struct.pack('<I', tx.nConsensusBranchId),
    )

    digest.update(header_digest(tx))
    digest.update(transparent_digest(tx))
    digest.update(sapling_digest(tx))
    digest.update(orchard_digest(tx))

    return digest.digest()

# Authorizing Data Commitment

def auth_digest(tx):
    digest = blake2b(
        digest_size=32,
        person=b'ZTxAuthHash_' + struct.pack('<I', tx.nConsensusBranchId),
    )

    digest.update(transparent_scripts_digest(tx))
    digest.update(sapling_auth_digest(tx))
    digest.update(orchard_auth_digest(tx))

    return digest.digest()

# Signatures

class TransparentInput(object):
    def __init__(self, nIn, rand, limit=MAX_MONEY):
        self.nIn = nIn
        self.scriptPubKey = Script(rand)
        self.amount = rand.u64() % (limit + 1)

def signature_digest(tx, t_inputs, nHashType, txin):
    digest = blake2b(
        digest_size=32,
        person=b'ZcashTxHash_' + struct.pack('<I', tx.nConsensusBranchId),
    )

    digest.update(header_digest(tx))
    digest.update(transparent_sig_digest(tx, t_inputs, nHashType, txin))
    digest.update(sapling_digest(tx))
    digest.update(orchard_digest(tx))

    return digest.digest()

def transparent_sig_digest(tx, t_inputs, nHashType, txin):
    # If we are producing a hash for either a coinbase transaction, or a
    # non-coinbase transaction that has no transparent inputs, the value of
    # ``transparent_sig_digest`` is identical to the value specified in section
    # T.2 <https://zips.z.cash/zip-0244#t-2-transparent-digest>.

    if tx.is_coinbase() or len(tx.vin) == 0:
        return transparent_digest(tx)
    else:
        digest = blake2b(digest_size=32, person=b'ZTxIdTranspaHash')
        digest.update(hash_type(tx, nHashType, txin))
        digest.update(prevouts_sig_digest(tx, nHashType))
        digest.update(amounts_sig_digest(t_inputs, nHashType))
        digest.update(scriptpubkeys_sig_digest(t_inputs, nHashType))
        digest.update(sequence_sig_digest(tx, nHashType))
        digest.update(outputs_sig_digest(tx, nHashType, txin))
        digest.update(txin_sig_digest(tx, txin))

        return digest.digest()

def hash_type(tx, nHashType, txin):
    if txin is None:
        # Sapling Spend or Orchard Action
        assert nHashType == SIGHASH_ALL
    else:
        # Transparent input
        assert nHashType in [
            SIGHASH_ALL,
            SIGHASH_NONE,
            SIGHASH_SINGLE,
            SIGHASH_ALL | SIGHASH_ANYONECANPAY,
            SIGHASH_NONE | SIGHASH_ANYONECANPAY,
            SIGHASH_SINGLE | SIGHASH_ANYONECANPAY,
        ]
        assert (nHashType & 0x1f) != SIGHASH_SINGLE or 0 <= txin.nIn and txin.nIn < len(tx.vout)
    return struct.pack('B', nHashType)

def prevouts_sig_digest(tx, nHashType):
    # If the SIGHASH_ANYONECANPAY flag is not set:
    if not (nHashType & SIGHASH_ANYONECANPAY):
        return getHashPrevouts(tx, b'ZTxIdPrevoutHash')
    else:
        return blake2b(digest_size=32, person=b'ZTxIdPrevoutHash').digest()

def amounts_sig_digest(t_inputs, nHashType):
    # If the SIGHASH_ANYONECANPAY flag is not set:
    if not (nHashType & SIGHASH_ANYONECANPAY):
        digest = blake2b(digest_size=32, person=b'ZTxTrAmountsHash')
        for x in t_inputs:
            digest.update(struct.pack('<Q', x.amount))
        return digest.digest()
    else:
        return blake2b(digest_size=32, person=b'ZTxTrAmountsHash').digest()

def scriptpubkeys_sig_digest(t_inputs, nHashType):
    # If the SIGHASH_ANYONECANPAY flag is not set:
    if not (nHashType & SIGHASH_ANYONECANPAY):
        digest = blake2b(digest_size=32, person=b'ZTxTrScriptsHash')
        for x in t_inputs:
            digest.update(bytes(x.scriptPubKey))
        return digest.digest()
    else:
        return blake2b(digest_size=32, person=b'ZTxTrScriptsHash').digest()

def sequence_sig_digest(tx, nHashType):
    # if the SIGHASH_ANYONECANPAY flag is not set:
    if not (nHashType & SIGHASH_ANYONECANPAY):
        return getHashSequence(tx, b'ZTxIdSequencHash')
    else:
        return blake2b(digest_size=32, person=b'ZTxIdSequencHash').digest()

def outputs_sig_digest(tx, nHashType, txin):
    # If the sighash type is neither SIGHASH_SINGLE nor SIGHASH_NONE:
    if (nHashType & 0x1f) != SIGHASH_SINGLE and (nHashType & 0x1f) != SIGHASH_NONE:
        return getHashOutputs(tx, b'ZTxIdOutputsHash')

    # If the sighash type is SIGHASH_SINGLE and the signature hash is being computed for
    # the transparent input at a particular index, and a transparent output appears in the
    # transaction at that index:
    elif (nHashType & 0x1f) == SIGHASH_SINGLE and 0 <= txin.nIn and txin.nIn < len(tx.vout):
        digest = blake2b(digest_size=32, person=b'ZTxIdOutputsHash')
        digest.update(bytes(tx.vout[txin.nIn]))
        return digest.digest()

    else:
        return blake2b(digest_size=32, person=b'ZTxIdOutputsHash').digest()

def txin_sig_digest(tx, txin):
    digest = blake2b(digest_size=32, person=b'Zcash___TxInHash')
    if txin is not None:
        digest.update(bytes(tx.vin[txin.nIn].prevout))
        digest.update(struct.pack('<Q', txin.amount))
        digest.update(bytes(txin.scriptPubKey))
        digest.update(struct.pack('<I', tx.vin[txin.nIn].nSequence))
    return digest.digest()

def randbytes(rng):
    def generate_randbytes(l):
        ret = []
        while len(ret) < l:
            ret.append(rng.randrange(0, 256))
        return bytes(ret)
    rand = Rand(generate_randbytes)
    return rand

def generate_sighashes_and_txin(tx, t_inputs, rand):
     # If there are any non-dummy transparent inputs, derive a corresponding transparent sighash.
    if len(t_inputs) > 0:
        txin = rand.a(t_inputs)
    else:
        txin = None

    sighash_shielded = signature_digest(tx, t_inputs, SIGHASH_ALL, None)
    other_sighashes = {
        nHashType: None if txin is None else signature_digest(tx, t_inputs, nHashType, txin)
        for nHashType in ([
            SIGHASH_ALL,
            SIGHASH_NONE,
            SIGHASH_SINGLE,
            SIGHASH_ALL | SIGHASH_ANYONECANPAY,
            SIGHASH_NONE | SIGHASH_ANYONECANPAY,
            SIGHASH_SINGLE | SIGHASH_ANYONECANPAY,
        ] if txin is None or txin.nIn < len(tx.vout) else [
            SIGHASH_ALL,
            SIGHASH_NONE,
            SIGHASH_ALL | SIGHASH_ANYONECANPAY,
            SIGHASH_NONE | SIGHASH_ANYONECANPAY,
        ])
    }
    return [sighash_shielded, other_sighashes, txin]
