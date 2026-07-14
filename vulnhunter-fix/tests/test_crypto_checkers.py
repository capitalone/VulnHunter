"""Coverage tests for crypto-trust-chain-checkers.py (REQ-CWE-009)."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"


@pytest.fixture(scope="module")
def crypto():
    spec = importlib.util.spec_from_file_location(
        "crypto_ttc", SCRIPTS / "crypto-trust-chain-checkers.py"
    )
    m = importlib.util.module_from_spec(spec)
    sys.modules["crypto_ttc"] = m  # required so @dataclass can resolve annotations
    spec.loader.exec_module(m)
    return m


# ---- helpers ----

def test_unquote_strips_matching_double(crypto):
    assert crypto._unquote('"hello"') == "hello"


def test_unquote_strips_matching_single(crypto):
    assert crypto._unquote("'hello'") == "hello"


def test_unquote_preserves_mismatched(crypto):
    assert crypto._unquote('"hello\'') == '"hello\''


def test_unquote_preserves_short(crypto):
    assert crypto._unquote("a") == "a"
    assert crypto._unquote("") == ""


def test_strip_inline_comment_removes_trailing(crypto):
    assert crypto._strip_inline_comment("value  # a comment") == "value"


def test_strip_inline_comment_preserves_hash_in_regex(crypto):
    assert crypto._strip_inline_comment("^regex#with#hash$") == "^regex#with#hash$"


def test_strip_inline_comment_empty(crypto):
    assert crypto._strip_inline_comment("") == ""


def test_load_yaml_flat_reads_repo_files(crypto):
    algo = crypto._load_yaml_flat(crypto.ALGO_YAML)
    assert isinstance(algo, dict)
    assert len(algo) > 0


def test_load_yaml_flat_custom(crypto, tmp_path):
    yml = tmp_path / "t.yaml"
    yml.write_text(
        "# a comment\n"
        "cat_a:\n"
        "  - alpha\n"
        "  - 'beta'\n"
        "  - 'gamma'  # trailing comment\n"
        "cat_b:\n"
        "  - only\n",
        encoding="utf-8",
    )
    got = crypto._load_yaml_flat(yml)
    assert got["cat_a"] == ["alpha", "beta", "gamma"]
    assert got["cat_b"] == ["only"]


def test_added_lines_extracts_pluses_ignores_header(crypto):
    diff = "+++ b/foo.py\n+added line\n-removed line\n context\n+another\n"
    assert crypto._added_lines(diff) == ["added line", "another"]


# ---- check_algorithm_approved ----

def test_algorithm_approved_hit(crypto):
    ref = {"symmetric": ["AES-GCM"], "asymmetric": [], "hash": [], "kdf": [], "mac": [],
           "symmetric_denied": [], "asymmetric_denied": [], "hash_denied": [], "kdf_denied": [], "mac_denied": []}
    diff = "+key = AES-GCM(key)\n"
    ok, evidence = crypto.check_algorithm_approved(diff, ref)
    assert ok is True
    assert "AES-GCM" in evidence


def test_algorithm_denied_wins(crypto):
    ref = {"symmetric": ["AES-GCM"], "symmetric_denied": ["DES"],
           "asymmetric": [], "asymmetric_denied": [],
           "hash": [], "hash_denied": [], "kdf": [], "kdf_denied": [], "mac": [], "mac_denied": []}
    diff = "+cipher = DES.new(key)\n+other = AES-GCM(k)\n"
    ok, evidence = crypto.check_algorithm_approved(diff, ref)
    assert ok is False
    assert "DES" in evidence


def test_algorithm_no_match(crypto):
    ref = {"symmetric": ["AES-GCM"], "symmetric_denied": ["DES"],
           "asymmetric": [], "asymmetric_denied": [],
           "hash": [], "hash_denied": [], "kdf": [], "kdf_denied": [], "mac": [], "mac_denied": []}
    diff = "+something unrelated\n"
    ok, evidence = crypto.check_algorithm_approved(diff, ref)
    assert ok is False
    assert "no approved algorithm" in evidence


def test_algorithm_ecdsa_not_flagged_by_dsa_substring(crypto):
    """Allow-path guard (peer review major): `DSA` is denied and is a
    substring of the approved `ECDSA-P256`. Word-boundary matching must
    approve the ECDSA fix rather than falsely deny it."""
    ref = {"symmetric": [], "asymmetric": ["ECDSA-P256", "ECDSA-P384"],
           "hash": [], "kdf": [], "mac": [],
           "symmetric_denied": [], "asymmetric_denied": ["DSA", "ECDSA-P224"],
           "hash_denied": [], "kdf_denied": [], "mac_denied": []}
    diff = "+sig = ecdsa.sign(key, ECDSA-P256)\n"
    ok, evidence = crypto.check_algorithm_approved(diff, ref)
    assert ok is True, f"ECDSA-P256 wrongly denied: {evidence}"
    assert "ECDSA-P256" in evidence


def test_algorithm_standalone_dsa_still_denied(crypto):
    """The word-boundary fix must NOT weaken detection of a genuine
    standalone DSA token."""
    ref = {"symmetric": [], "asymmetric": ["ECDSA-P256"],
           "hash": [], "kdf": [], "mac": [],
           "symmetric_denied": [], "asymmetric_denied": ["DSA"],
           "hash_denied": [], "kdf_denied": [], "mac_denied": []}
    diff = "+key = dsa.generate_private_key()\n"
    ok, evidence = crypto.check_algorithm_approved(diff, ref)
    assert ok is False
    assert "DSA" in evidence


# ---- check_key_source_approved ----

def test_key_source_chamber_approved(crypto):
    ref = {"chamber": ["ChamberClient"], "denied": []}
    diff = "+secret = ChamberClient().fetch('key')\n"
    ok, evidence = crypto.check_key_source_approved(diff, ref)
    assert ok is True
    assert "chamber" in evidence


def test_key_source_kms_approved(crypto):
    ref = {"aws_kms": ["KMS.Decrypt"], "denied": []}
    diff = "+key = KMS.Decrypt(blob)\n"
    ok, evidence = crypto.check_key_source_approved(diff, ref)
    assert ok is True


def test_key_source_denied_wins(crypto):
    ref = {"chamber": ["ChamberClient"], "denied": ["HARDCODED_KEY"]}
    diff = "+key = HARDCODED_KEY  # oops\n+other = ChamberClient()\n"
    ok, evidence = crypto.check_key_source_approved(diff, ref)
    assert ok is False


def test_key_source_no_match(crypto):
    ref = {"chamber": ["ChamberClient"], "denied": []}
    diff = "+irrelevant\n"
    ok, evidence = crypto.check_key_source_approved(diff, ref)
    assert ok is False
    assert "no approved key-source" in evidence


def test_algorithm_denied_punctuation_patterns(crypto):
    """F2 (segment-review S6): commit 73d0c70's unconditional \\b-wrap
    broke denied patterns that start/end with punctuation — Java MD5/SHA1
    idioms passed the crypto gate silently. RED guard for the conditional-\\b
    fix in _token_present. Uses ISOLATED contexts (no word char flanking the
    punctuation) which is where the \\b-wrap actually fails, and asserts the
    DENIED evidence (not just ok is False, which 'no approved algo' also
    returns)."""
    ref = {"symmetric": [], "asymmetric": [], "kdf": [], "mac": [],
           "symmetric_denied": [], "asymmetric_denied": [], "kdf_denied": [], "mac_denied": [],
           "hash": [],
           "hash_denied": ['.MD5(', 'MessageDigest.getInstance("MD5"',
                           'MessageDigest.getInstance("SHA1"']}
    for snippet in ('+digest = .MD5(data)\n',
                    '+md = MessageDigest.getInstance("MD5")\n',
                    '+md = MessageDigest.getInstance("SHA1")\n'):
        ok, evidence = crypto.check_algorithm_approved(snippet, ref)
        assert ok is False and "denied algorithm present" in evidence, \
            f"punctuation denied pattern missed in {snippet!r}: {evidence}"


def test_key_source_denied_case_insensitive(crypto):
    """F3a (segment-review S6): the key-source check was case-sensitive
    (unlike the algorithm check), so a lowercased bare env var bypassed the
    deny. RED guard for the .lower() fix — asserts the DENIED evidence."""
    ref = {"denied": ["SECRET_KEY = os.getenv"]}
    diff = "+secret_key = os.getenv('K')\n"   # lowercased — must still be denied
    ok, evidence = crypto.check_key_source_approved(diff, ref)
    assert ok is False and "denied key source" in evidence, \
        f"lowercased bare env var bypassed the deny: {evidence}"


def test_key_source_annotation_requires_window(crypto):
    """F3b (segment-review S6): a bare KEY_SOURCE_APPROVED annotation
    ANYWHERE green-lit the whole diff. The doc says it must sit within 2 lines
    of the key. RED guard: an annotation with no key nearby must NOT approve."""
    ref = {"annotation": ["KEY_SOURCE_APPROVED:"], "denied": []}
    # Annotation floating with no key-source context within 2 lines below.
    diff = (
        "+# KEY_SOURCE_APPROVED: reviewed by security\n"
        "+import os\n"
        "+def unrelated():\n"
        "+    return compute_stuff()\n"
    )
    ok, evidence = crypto.check_key_source_approved(diff, ref)
    assert ok is False, f"floating annotation wrongly approved: {evidence}"


def test_key_source_annotation_within_window_approves(crypto):
    """The window fix must still approve a properly-placed annotation."""
    ref = {"annotation": ["KEY_SOURCE_APPROVED:"], "denied": []}
    diff = (
        "+# KEY_SOURCE_APPROVED: custom HSM read, reviewed\n"
        "+secret_key = hsm.read_key('signing')\n"
    )
    ok, evidence = crypto.check_key_source_approved(diff, ref)
    assert ok is True, f"properly-annotated key source wrongly rejected: {evidence}"



# ---- check_key_rotation_present ----

def test_rotation_rotate_key(crypto):
    ok, ev = crypto.check_key_rotation_present("+rotate_key(kid=1)\n")
    assert ok is True
    assert "rotate_key" in ev


def test_rotation_kms_schedule(crypto):
    ok, ev = crypto.check_key_rotation_present("+KMS.ScheduleKeyDeletion(k)\n")
    assert ok is True


def test_rotation_annotation(crypto):
    ok, ev = crypto.check_key_rotation_present("+@rotation_schedule\n+def f(): pass\n")
    assert ok is True


def test_rotation_cron(crypto):
    ok, ev = crypto.check_key_rotation_present("+cron: 0 0 * * * rotate\n")
    assert ok is True


def test_rotation_missing(crypto):
    ok, ev = crypto.check_key_rotation_present("+no rotation here\n")
    assert ok is False
    assert "no rotation" in ev


# ---- check_transport_encrypted ----

def test_transport_https_approved(crypto):
    ok, ev = crypto.check_transport_encrypted("+url = 'https://example.com'\n")
    assert ok is True


def test_transport_tls_config(crypto):
    ok, ev = crypto.check_transport_encrypted("+cfg := tls.Config{}\n")
    assert ok is True


def test_transport_denied_http(crypto):
    ok, ev = crypto.check_transport_encrypted("+url = 'http://example.com'\n")
    assert ok is False
    assert "denied" in ev


def test_transport_http_localhost_not_denied(crypto):
    """http://localhost should NOT trigger denied pattern (dev-only)."""
    ok, ev = crypto.check_transport_encrypted("+url = 'http://localhost:8080'\n")
    # Neither approved nor denied — falls through
    assert ok is False
    assert "no transport indicator" in ev


def test_transport_verify_false_denied(crypto):
    ok, ev = crypto.check_transport_encrypted("+requests.get(url, verify=False)\n")
    assert ok is False
    assert "denied" in ev


def test_transport_missing(crypto):
    ok, ev = crypto.check_transport_encrypted("+no protocol\n")
    assert ok is False
    assert "no transport indicator" in ev


# ---- run_checkers integration ----

def test_run_checkers_end_to_end(crypto):
    # Uses the actual repo YAML files
    diff = (
        "+++ b/foo.py\n"
        "+from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
        "+key = ChamberClient().fetch('key')\n"
        "+rotate_key(key_id)\n"
        "+url = 'https://api.example.com'\n"
    )
    result = crypto.run_checkers(diff)
    # We don't assert specific booleans because they depend on the exact
    # contents of the YAML reference files — but the invocation must return
    # a fully populated TrustChainResult.
    assert result.checker_version == "1"
    assert isinstance(result.algorithm_approved, bool)
    assert isinstance(result.key_source_approved, bool)
    assert isinstance(result.key_rotation_present, bool)
    assert isinstance(result.transport_encrypted, bool)


# ---- main() CLI ----

def test_main_writes_json(crypto, tmp_path, capsys):
    diff = tmp_path / "d.diff"
    diff.write_text("+innocuous\n", encoding="utf-8")
    assert crypto.main(["c", "--diff", str(diff)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert "algorithm_approved" in payload
    assert payload["checker_version"] == "1"


def test_main_emit_sidecar(crypto, tmp_path, capsys):
    diff = tmp_path / "d.diff"
    diff.write_text("+harmless\n", encoding="utf-8")
    assert crypto.main(["c", "--diff", str(diff), "--emit-sidecar", "VULN-9"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["vuln_id"] == "VULN-9"
    assert "crypto_trust_chain" in payload


def test_main_missing_diff_file(crypto, tmp_path, capsys):
    missing = tmp_path / "nope.diff"
    assert crypto.main(["c", "--diff", str(missing)]) == 2
    assert "error:" in capsys.readouterr().err


def test_read_diff_stdin(crypto, monkeypatch):
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO("+from stdin\n"))
    assert crypto._read_diff("-") == "+from stdin\n"


# ---- weak key parameters (synthesized review S8, B3) ----

def _ref_with_constants(**consts):
    """A ref whose only approved identifier is RSA-OAEP-SHA256, plus the
    constants block that _load_yaml_flat used to drop."""
    return {
        "symmetric": [], "asymmetric": ["RSA-OAEP-SHA256"], "hash": [], "kdf": [], "mac": [],
        "symmetric_denied": [], "asymmetric_denied": [], "hash_denied": [],
        "kdf_denied": [], "mac_denied": [],
        "constants": consts,
    }


def test_load_yaml_flat_parses_nested_constants(crypto, tmp_path):
    """B3: the nested `constants:` scalar map must load as a dict with int
    values, not the empty list the flat loader used to produce."""
    yml = tmp_path / "t.yaml"
    yml.write_text(
        "asymmetric:\n  - RSA-OAEP-SHA256\n"
        "constants:\n  rsa_min_bits: 3072\n  pbkdf2_min_iterations: 100000\n",
        encoding="utf-8",
    )
    got = crypto._load_yaml_flat(yml)
    assert got["asymmetric"] == ["RSA-OAEP-SHA256"]
    assert isinstance(got["constants"], dict), "constants must parse as a mapping, not a list"
    assert got["constants"]["rsa_min_bits"] == 3072
    assert got["constants"]["pbkdf2_min_iterations"] == 100000


def test_real_yaml_constants_are_live(crypto):
    """B3: the committed approved-crypto-algorithms.yaml constants must be
    reachable (were dead — parsed to [] and read by nothing)."""
    algo = crypto._load_yaml_flat(crypto.ALGO_YAML)
    assert isinstance(algo.get("constants"), dict)
    assert algo["constants"]["rsa_min_bits"] == 3072


def test_weak_rsa_2048_denied(crypto):
    """B3: a 2048-bit RSA fix must NOT be algorithm_approved even though its
    identifier (RSA-OAEP-SHA256) is on the approved list — bit size is the
    fail-open the constants block exists to close."""
    ref = _ref_with_constants(rsa_min_bits=3072)
    diff = "+priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)  # RSA-OAEP-SHA256\n"
    ok, evidence = crypto.check_algorithm_approved(diff, ref)
    assert ok is False, "sub-3072 RSA passed as approved (fail-open)"
    assert "2048" in evidence and "rsa" in evidence.lower()


def test_weak_rsa_1024_denied(crypto):
    ref = _ref_with_constants(rsa_min_bits=3072)
    diff = "+key = RSA.generate(1024)  # RSA-OAEP-SHA256\n"
    ok, evidence = crypto.check_algorithm_approved(diff, ref)
    assert ok is False
    assert "1024" in evidence


def test_strong_rsa_4096_still_approved(crypto):
    """Allow-path guard: a compliant 4096-bit RSA fix must remain approved —
    the bit check must not over-deny. Identifier is code-grounded (a string
    literal), not a comment, since comment-based approval is now rejected."""
    ref = _ref_with_constants(rsa_min_bits=3072)
    diff = ('+priv = rsa.generate_private_key(public_exponent=65537, key_size=4096)\n'
            '+algo_id = "RSA-OAEP-SHA256"\n')
    ok, evidence = crypto.check_algorithm_approved(diff, ref)
    assert ok is True, f"strong RSA wrongly denied: {evidence}"


def test_aes_256_not_flagged_as_weak_rsa(crypto):
    """Allow-path guard: 256 is a valid AES key length; without RSA context it
    must not trip the weak-RSA-bits check (256 < 3072)."""
    ref = {
        "symmetric": ["AES-256-GCM"], "asymmetric": [], "hash": [], "kdf": [], "mac": [],
        "symmetric_denied": [], "asymmetric_denied": [], "hash_denied": [],
        "kdf_denied": [], "mac_denied": [],
        "constants": {"rsa_min_bits": 3072},
    }
    diff = ('+key = AESGCM.generate_key(bit_length=256)\n'
            '+algo = "AES-256-GCM"\n')
    ok, evidence = crypto.check_algorithm_approved(diff, ref)
    assert ok is True, f"AES-256 misflagged as weak RSA: {evidence}"


def test_weak_pbkdf2_iterations_denied(crypto):
    """B3: PBKDF2 below the iteration floor must be denied on a PBKDF2 line."""
    ref = _ref_with_constants(pbkdf2_min_iterations=100000)
    ref["kdf"] = ["PBKDF2-HMAC-SHA256"]
    diff = "+kdf = PBKDF2HMAC(algorithm=SHA256, iterations=1000)  # PBKDF2-HMAC-SHA256\n"
    ok, evidence = crypto.check_algorithm_approved(diff, ref)
    assert ok is False
    assert "1000" in evidence


# --- S7 (12-seg review): crypto checker must default-deny ------------------

def test_approved_identifier_in_comment_does_not_approve(crypto):
    """S7a: an approved identifier sitting in a COMMENT green-lit weak code
    (no comment stripping). `weak_custom_xor(key)  # migrated to AES-256-GCM`
    must NOT count as an approved algorithm."""
    ref = {"symmetric": ["AES-256-GCM"], "asymmetric": [], "hash": [], "kdf": [], "mac": [],
           "symmetric_denied": [], "asymmetric_denied": [], "hash_denied": [],
           "kdf_denied": [], "mac_denied": [], "constants": {}}
    diff = "+cipher = weak_custom_xor(key)  # migrated to AES-256-GCM\n"
    ok, evidence = crypto.check_algorithm_approved(diff, ref)
    assert ok is False, f"comment green-lit weak code: {evidence}"


def test_ecb_mode_idiom_denied(crypto):
    """S7b: the yaml denies the string 'AES-ECB' but not the actual Python
    idiom modes.ECB(); Cipher(algorithms.AES(k), modes.ECB()) passed. Assert it
    is DENIED (not merely unapproved) so the test can't pass vacuously."""
    ref = crypto._load_yaml_flat(crypto.ALGO_YAML)
    diff = '+cipher = Cipher(algorithms.AES(key), modes.ECB())\n+algo = "AES-256-GCM"\n'
    ok, evidence = crypto.check_algorithm_approved(diff, ref)
    assert ok is False, f"modes.ECB() not denied: {evidence}"
    assert "denied" in evidence.lower() and "ecb" in evidence.lower(), (
        f"ECB not denied for the right reason: {evidence}"
    )


def test_weak_ecc_curve_denied(crypto):
    """S7c: ecc_min_bits floor was declared but never enforced — ec.SECP192R1()
    returned approved. The diff carries an approved identifier (so it would be
    approved today), but the sub-256-bit curve must force denial."""
    ref = _ref_with_constants(ecc_min_bits=256)
    ref["asymmetric"] = ["ECDSA-P256"]
    diff = '+key = ec.generate_private_key(ec.SECP192R1())\n+algo = "ECDSA-P256"\n'
    ok, evidence = crypto.check_algorithm_approved(diff, ref)
    assert ok is False, f"weak ECC curve approved: {evidence}"
    assert "192" in evidence or "ecc" in evidence.lower()


def test_weak_rsa_size_denied_when_off_the_rsa_line(crypto):
    """S7d: a weak RSA modulus on a different line than the RSA token escaped
    the same-line check. RSA context anywhere in the diff + a weak modulus
    must deny."""
    ref = _ref_with_constants(rsa_min_bits=3072)
    ref["asymmetric"] = ["RSA-OAEP-SHA256"]
    diff = (
        "+key = rsa.generate_private_key(  # RSA-OAEP-SHA256\n"
        "+    public_exponent=65537,\n"
        "+    key_size=2048,\n"
        "+)\n"
    )
    ok, evidence = crypto.check_algorithm_approved(diff, ref)
    assert ok is False, f"off-line weak RSA size escaped: {evidence}"


def test_strong_ecc_and_rsa_still_approved(crypto):
    """Allow-path guard: P-256 and RSA-4096 must remain approved after the
    default-deny hardening. Identifiers are code-grounded (string literals)."""
    ref = _ref_with_constants(rsa_min_bits=3072, ecc_min_bits=256)
    ref["asymmetric"] = ["ECDSA-P256", "RSA-OAEP-SHA256"]
    ecc_diff = '+key = ec.generate_private_key(ec.SECP256R1())\n+algo = "ECDSA-P256"\n'
    assert crypto.check_algorithm_approved(ecc_diff, ref)[0] is True
    rsa_diff = ('+key = rsa.generate_private_key(public_exponent=65537, key_size=4096)\n'
                '+algo = "RSA-OAEP-SHA256"\n')
    assert crypto.check_algorithm_approved(rsa_diff, ref)[0] is True

