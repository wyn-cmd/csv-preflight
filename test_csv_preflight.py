# Tests for csv_preflight, built from small files written to a temp directory
import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import csv_preflight

HERE = os.path.dirname(os.path.abspath(__file__))


# Write bytes to a temp file and hand the path back
def write_temp(directory, name, data):
    path = os.path.join(directory, name)
    with open(path, "wb") as handle:
        handle.write(data)
    return path


# Group findings by code so assertions stay readable
def codes(result):
    return [finding["code"] for finding in result["findings"]]


class EncodingTests(unittest.TestCase):
    def test_plain_utf8_is_recognised(self):
        encoding, source = csv_preflight.detect_encoding(b"a,b\n1,2\n")
        self.assertEqual(encoding, "utf-8")
        self.assertEqual(source, "utf-8-validated")

    def test_utf8_bom_is_reported_as_bom_source(self):
        raw = b"\xef\xbb\xbfa,b\n1,2\n"
        encoding, source = csv_preflight.detect_encoding(raw)
        self.assertEqual(encoding, "utf-8-sig")
        self.assertEqual(source, "bom")

    def test_utf16_le_bom_is_detected(self):
        raw = b"\xff\xfe" + "a,b\n1,2\n".encode("utf-16-le")
        encoding, _ = csv_preflight.detect_encoding(raw)
        self.assertEqual(encoding, "utf-16-le")

    def test_utf32_le_bom_is_detected_before_utf16(self):
        raw = b"\xff\xfe\x00\x00" + "a,b\n".encode("utf-32-le")
        encoding, _ = csv_preflight.detect_encoding(raw)
        self.assertEqual(encoding, "utf-32-le")

    def test_invalid_utf8_falls_back(self):
        encoding, source = csv_preflight.detect_encoding(b"caf\xe9,2\n")
        self.assertEqual(source, "fallback")
        self.assertIn(encoding, ("cp1252", "latin-1"))


class DelimiterTests(unittest.TestCase):
    def test_comma_wins_on_comma_file(self):
        text = "a,b,c\n1,2,3\n4,5,6\n"
        self.assertEqual(csv_preflight.sniff_delimiter(text)[0], ",")

    def test_semicolon_wins_on_semicolon_file(self):
        text = "a;b;c\n1;2;3\n4;5;6\n"
        self.assertEqual(csv_preflight.sniff_delimiter(text)[0], ";")

    def test_tab_wins_on_tab_file(self):
        text = "a\tb\tc\n1\t2\t3\n4\t5\t6\n"
        self.assertEqual(csv_preflight.sniff_delimiter(text)[0], "\t")

    def test_quoted_delimiter_is_not_counted(self):
        self.assertEqual(csv_preflight.count_unquoted('a,"b,c",d', ","), 2)


class AnalysisTests(unittest.TestCase):
    def test_clean_file_has_no_findings(self):
        findings, stats = csv_preflight.analyse("id,name\n1,ada\n2,grace\n")
        self.assertEqual(findings, [])
        self.assertEqual(stats["columns"], 2)
        self.assertEqual(stats["data_rows"], 2)

    def test_duplicate_header_is_an_error(self):
        findings, _ = csv_preflight.analyse("id,Name,name\n1,a,b\n")
        self.assertIn("CF001", [f["code"] for f in findings])

    def test_empty_header_cell_is_an_error(self):
        findings, _ = csv_preflight.analyse("id,,name\n1,a,b\n")
        self.assertIn("CF002", [f["code"] for f in findings])

    def test_padded_header_is_a_warning(self):
        findings, _ = csv_preflight.analyse(" id,name \n1,a\n")
        self.assertIn("CF003", [f["code"] for f in findings])

    def test_ragged_row_reports_its_line_number(self):
        findings, stats = csv_preflight.analyse("id,name\n1,ada\n2,grace,extra\n")
        ragged = [f for f in findings if f["code"] == "CF004"]
        self.assertEqual(len(ragged), 1)
        self.assertEqual(ragged[0]["line"], 3)
        self.assertEqual(stats["ragged_rows"], 1)

    def test_blank_record_is_reported(self):
        findings, stats = csv_preflight.analyse("id,name\n1,ada\n\n2,grace\n")
        self.assertIn("CF005", [f["code"] for f in findings])
        self.assertEqual(stats["blank_records"], 1)

    def test_multiline_quoted_field_keeps_line_numbers(self):
        text = 'id,note\n1,"first line\nsecond line"\n2,plain\n'
        findings, stats = csv_preflight.analyse(text)
        self.assertEqual(findings, [])
        self.assertEqual(stats["data_rows"], 2)

    def test_single_column_header_warns(self):
        findings, _ = csv_preflight.analyse("id\n1\n2\n")
        self.assertIn("CF009", [f["code"] for f in findings])


class FileTests(unittest.TestCase):
    def test_nul_bytes_are_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_temp(tmp, "binary.csv", b"id,name\n1,a\x00b\n")
            result = csv_preflight.inspect_file(path)
        self.assertIn("CF006", codes(result))
        self.assertFalse(result["ok"])

    def test_mixed_line_endings_are_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_temp(tmp, "mixed.csv", b"id,name\r\n1,ada\n2,grace\r\n")
            result = csv_preflight.inspect_file(path)
        self.assertIn("CF007", codes(result))

    def test_utf16_file_is_not_flagged_as_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            body = "id,name\n1,ada\n".encode("utf-16-le")
            path = write_temp(tmp, "utf16.csv", b"\xff\xfe" + body)
            result = csv_preflight.inspect_file(path)
        self.assertEqual(result["encoding"], "utf-16-le")
        self.assertNotIn("CF006", codes(result))
        self.assertIn("CF008", codes(result))
        self.assertEqual(result["columns"], 2)

    def test_oversized_file_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_temp(tmp, "big.csv", b"id,name\n1,ada\n")
            with self.assertRaises(ValueError):
                csv_preflight.inspect_file(path, max_bytes=4)


class CommandLineTests(unittest.TestCase):
    def test_clean_file_exits_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_temp(tmp, "clean.csv", b"id,name\n1,ada\n")
            result = csv_preflight.main([path, "--quiet"])
        self.assertEqual(result, 0)

    def test_broken_file_exits_two(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_temp(tmp, "broken.csv", b"id,name\n1,ada,extra\n")
            result = csv_preflight.main([path, "--quiet"])
        self.assertEqual(result, 2)

    def test_json_output_parses(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_temp(tmp, "clean.csv", b"id,name\n1,ada\n")
            completed = subprocess.run(
                [sys.executable, os.path.join(HERE, "csv_preflight.py"), path, "--format", "json"],
                capture_output=True,
                text=True,
            )
        payload = json.loads(completed.stdout)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["delimiter"], ",")
        self.assertEqual(completed.returncode, 0)

    def test_declared_delimiter_overrides_guessing(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_temp(tmp, "semicolon.csv", b"id;name\n1;ada\n")
            declared = csv_preflight.inspect_file(path, delimiter=";")
            guessed = csv_preflight.inspect_file(path)
        self.assertTrue(declared["delimiter_declared"])
        self.assertFalse(guessed["delimiter_declared"])
        self.assertEqual(declared["delimiter"], ";")


if __name__ == "__main__":
    unittest.main()
