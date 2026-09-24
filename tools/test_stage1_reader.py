import tempfile
import unittest
from pathlib import Path
from verify_stage1_ovmf import input_hashes, validate_case


class ReaderTests(unittest.TestCase):
    def scalar(self):
        return dict(name="strb", granule="4096", upper="false", status="1", provider="0",
                    retired="3", blocks="3", fetch="3", data="1", completed="1", esr="0x0",
                    far="0x0", reply="0", fsc="0", **{"pass": "true"})

    def test_actual_counts_and_fault_fields(self):
        self.assertTrue(validate_case(self.scalar())["passed"])
        fault = self.scalar()
        fault.update(name="pair-store-af", status="17", retired="1", blocks="2", fetch="2",
                     completed="0", esr="0x9600004b", far="0x20005000", reply="1", fsc="11")
        self.assertTrue(validate_case(fault)["passed"])
        for key, value in [("esr", "0x9600000b"), ("far", "0x10005000"), ("fsc", "7"),
                           ("completed", "1"), ("provider", "3")]:
            wrong = dict(fault, **{key: value})
            self.assertFalse(validate_case(wrong)["passed"], key)

    def test_success_marker_does_not_override_numeric_failure(self):
        for key, value in [("retired", "2"), ("blocks", "0"), ("data", "0"),
                           ("reply", "1"), ("esr", "NaN")]:
            self.assertFalse(validate_case(dict(self.scalar(), **{key: value}))["passed"], key)

    def test_unaligned_success_and_second_page_failure(self):
        for name in ("unaligned-load", "unaligned-store"):
            self.assertTrue(validate_case(dict(self.scalar(), name=name))["passed"])
        fault = dict(self.scalar(), name="unaligned-load-translation", status="17",
                     retired="1", blocks="2", fetch="2", completed="0",
                     reply="1", fsc="7", far="0x20005000", esr="0x96000007")
        self.assertTrue(validate_case(fault)["passed"])
        for key, value in [("completed", "1"), ("far", "0x20004ffc"),
                           ("esr", "0x96000021"), ("fsc", "33")]:
            self.assertFalse(validate_case(dict(fault, **{key: value}))["passed"], key)

    def test_unknown_duplicate_shape_and_missing_fields(self):
        self.assertFalse(validate_case(dict(self.scalar(), unexpected="0"))["passed"])
        missing = self.scalar()
        del missing["far"]
        self.assertFalse(validate_case(missing)["passed"])
        self.assertFalse(validate_case(dict(self.scalar(), name="invented"))["passed"])

    def test_same_basename_different_inputs_keep_each_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            inputs = {}
            for role in ["efi_probe", "ovmf_code", "ovmf_vars"]:
                path = Path(directory) / role / "same.bin"
                path.parent.mkdir()
                path.write_bytes(role.encode())
                inputs[role] = path
            result = input_hashes(inputs)
            self.assertEqual(set(result), set(inputs))
            self.assertEqual(len(set(result.values())), 3)
            inputs["ovmf_vars"].write_bytes(b"changed")
            after = input_hashes(inputs)
            self.assertNotEqual(after["ovmf_vars"], result["ovmf_vars"])
            self.assertEqual(after["efi_probe"], result["efi_probe"])


if __name__ == "__main__":
    unittest.main()
