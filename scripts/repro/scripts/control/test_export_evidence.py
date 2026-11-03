"""Offline export checks: temporary files only, no AWS imports or calls."""
import base64
import gzip
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import export_evidence as export


class ExportEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'source'
        (self.root / 'evidence' / 'nested').mkdir(parents=True)
        (self.root / 'state').mkdir()
        self.original = '{"note":"São Paulo; ação", "nullable":null, "empty":""}\n'.encode('utf-8')
        (self.root / 'evidence' / 'nested' / 'observed.json').write_bytes(self.original)
        (self.root / export.STATE_PATHS[0]).write_text('{"run_id":"fixture-r01"}', encoding='utf-8')

    def build(self, tag='R01'):
        return export.build_snapshot(self.root, tag)

    def local(self, descriptor, parts):
        destination = Path(self.temp.name) / 'local'
        destination.mkdir()
        (destination / 'descriptor.json').write_bytes(export.encoded_json(descriptor))
        for index, part in enumerate(parts):
            (destination / f'part-{index:04d}.b64').write_text(part, encoding='ascii')
        return destination

    def repack(self, descriptor, compressed, change):
        bundle = json.loads(gzip.decompress(compressed))
        change(bundle)
        raw = export.encoded_json(bundle)
        packed = gzip.compress(raw, mtime=0)
        encoded = base64.b64encode(packed)
        chunks = [encoded[start:start + export.PART_CHARS]
                  for start in range(0, len(encoded), export.PART_CHARS)]
        edited = {**descriptor, 'bundle_sha256': export.digest(packed),
                  'compressed_bytes': len(packed), 'uncompressed_bytes': len(raw),
                  'uncompressed_sha256': export.digest(raw), 'part_count': len(chunks)}
        return edited, chunks

    def test_round_trip_preserves_utf8_bytes_and_reports_all_hashes(self):
        descriptor, _, parts = self.build()
        destination = self.local(descriptor, parts)
        receipt = export.finish(destination, 'R01')
        self.assertTrue(receipt['success'])
        self.assertEqual(receipt['file_count'], 2)
        self.assertEqual((destination / 'files/evidence/nested/observed.json').read_bytes(), self.original)
        self.assertEqual(len(receipt['files']), 2)
        self.assertEqual((self.root / 'evidence/nested/observed.json').read_bytes(), self.original)
        self.assertTrue((destination / 'verified-receipt.json').is_file())

    def test_repeated_export_is_deterministic_and_never_overwrites_extraction(self):
        first = self.build()
        self.assertEqual(first, self.build())
        destination = self.local(first[0], first[2])
        export.finish(destination, 'R01')
        with self.assertRaises(ValueError):
            export.finish(destination, 'R01')
        self.assertEqual((destination / 'files/evidence/nested/observed.json').read_bytes(), self.original)

    def test_r02_requires_both_ledgers(self):
        with self.assertRaises(ValueError):
            self.build('R02')
        (self.root / export.STATE_PATHS[1]).write_text('{"run_id":"fixture-r02"}', encoding='utf-8')
        self.assertEqual(self.build('R02')[0]['file_count'], 3)

    def test_files_outside_allowlist_are_ignored(self):
        (self.root / 'config.json').write_text('{"password":"must-never-export"}', encoding='utf-8')
        (self.root / 'state/unrelated.json').write_text('{"password":"must-never-export"}', encoding='utf-8')
        (self.root / 'evidence/stdout.txt').write_text('excluded', encoding='utf-8')
        self.assertEqual(self.build()[0]['file_count'], 2)

    def test_secret_keys_values_and_serialized_envelopes_are_refused(self):
        for value in ({'Password': 'not-real'}, {'SecretString': 'not-real'},
                      {'stdout': '{"SecretAccessKey":"not-real"}'},
                      {'stdout': '{"SecretString":"not-real","same":1,"same":2}'},
                      {'stdout': '{"SecretString":"not-real","other":NaN}'},
                      {'note': 'ASIA' + 'Z' * 16},
                      {'note': 'SCRAM-SHA-256$4096:synthetic'}):
            with self.subTest(value_type=next(iter(value))):
                with self.assertRaises(ValueError):
                    export.reject_secrets(value)
        export.reject_secrets({'password_statements_executed': False,
                               'source_secret_arn': 'arn:aws:secretsmanager:us-east-1:111122223333:secret:example'})

    def test_typed_postgresql_acl_arrays_accept_only_expected_roles_and_privileges(self):
        fixtures = ('{}', '{=U/pg_database_owner,pg_database_owner=UC/pg_database_owner}',
                    '{postgres=CTc/postgres,lab_writer_source=c/postgres}',
                    '{lab_admin=CTc/lab_admin,dms_target=Cc/lab_admin}',
                    '{dms_source=arwdDxt/postgres,lab_reader_source=r/postgres}',
                    '{lab_writer_target=arwd/lab_admin,lab_reader_target=r/lab_admin}',
                    '{dms_target=U*C*/lab_admin}')
        for field in export.ACL_FIELDS:
            for value in fixtures:
                export.reject_secrets({field: value})
        for invalid in ('{unknown_user=U/postgres}', '{lab_admin=PASSWORD/postgres}',
                        '{"SecretString":"not-real"}', '{postgres=U/postgres} trailing',
                        '{postgres=U/postgres\n}', '{"postgres=U/postgres"}',
                        '{postgres=U/postgres\\}', '{=U/unknown_grantor}'):
            with self.subTest(invalid_case=fixtures.index('{}')):
                with self.assertRaises(ValueError):
                    export.reject_secrets({'acl': invalid})
        with self.assertRaises(ValueError):
            export.reject_secrets({'stdout': '{postgres=U/postgres}'})
        with self.assertRaises(ValueError):
            export.reject_secrets({'unrecognized_acl': '{postgres=U/postgres}'})

    def test_failure_report_emits_only_allowlisted_code_and_relative_path(self):
        hidden = ValueError('synthetic-secret-content-must-never-appear')
        hidden._export_relative_path = '../synthetic-secret-path.json'
        report = export.safe_failure(hidden)
        self.assertEqual(report['reason_code'], 'unclassified_error')
        self.assertNotIn('relative_path', report)
        self.assertNotIn('synthetic-secret', json.dumps(report))
        (self.root / 'evidence/bad.json').write_text('{"SecretString":"synthetic"}', encoding='utf-8')
        try:
            self.build()
        except ValueError as error:
            report = export.safe_failure(error)
        else:
            self.fail('Secret-bearing JSON was accepted')
        self.assertEqual(report['reason_code'], 'secret_key_refused')
        self.assertEqual(report['relative_path'], 'evidence/bad.json')
        self.assertNotIn('synthetic', json.dumps(report))

    def test_json_utf8_duplicate_keys_and_nan_are_refused(self):
        for invalid in (b'\xff', b'{"same":1,"same":2}', b'{"value":NaN}', b'not-json'):
            with self.subTest(kind=invalid[:5]):
                (self.root / 'evidence/invalid.json').write_bytes(invalid)
                with self.assertRaises((ValueError, UnicodeError)):
                    self.build()

    def test_symlink_files_and_directories_are_refused(self):
        link = self.root / 'evidence/link.json'
        try:
            link.symlink_to(self.root / export.STATE_PATHS[0])
        except OSError:
            # Some Windows installations require a privilege to create symlinks.
            with mock.patch.object(Path, 'is_symlink', return_value=True):
                with self.assertRaises(ValueError):
                    self.build()
        else:
            with self.assertRaises(ValueError):
                self.build()
            link.unlink()
            directory = self.root / 'evidence/linked-directory'
            directory.symlink_to(self.root / 'state', target_is_directory=True)
            with self.assertRaises(ValueError):
                self.build()

    def test_file_and_total_size_bounds(self):
        (self.root / 'evidence/large.json').write_bytes(b' ' * (export.MAX_FILE + 1))
        with self.assertRaises(ValueError):
            self.build()
        (self.root / 'evidence/large.json').unlink()
        with mock.patch.object(export, 'MAX_TOTAL', len(self.original)):
            with self.assertRaises(ValueError):
                self.build()

    def test_path_traversal_absolute_windows_and_reserved_paths_are_refused(self):
        for path in ('../outside.json', '/evidence/x.json', 'evidence/../x.json',
                     'evidence/a\\b.json', 'evidence/a.json:stream',
                     'evidence/CON.json', 'evidence/end. /x.json',
                     'state/unknown.json', 'config.json'):
            with self.subTest(path=path):
                with self.assertRaises(ValueError):
                    export.allowed_path(path)

    def test_bundle_hash_truncation_tag_and_file_hash_fail_closed(self):
        descriptor, compressed, parts = self.build()
        with self.assertRaises(ValueError):
            export.verify_bundle(descriptor, [b'AAAA' + parts[0][4:].encode()], 'R01')
        with self.assertRaises(ValueError):
            export.verify_bundle(descriptor, [part[:-4].encode() for part in parts], 'R01')
        with self.assertRaises(ValueError):
            export.verify_bundle(descriptor, [part.encode() for part in parts], 'R02')
        amended, chunks = self.repack(descriptor, compressed,
            lambda bundle: bundle['files'][0].update(sha256='0' * 64))
        with self.assertRaises(ValueError):
            export.verify_bundle(amended, chunks, 'R01')

    def test_even_correctly_rehashed_bundle_cannot_escape_allowlist(self):
        descriptor, compressed, _ = self.build()
        amended, parts = self.repack(descriptor, compressed,
            lambda bundle: bundle['files'][0].update(path='../outside.json'))
        with self.assertRaises(ValueError):
            export.verify_bundle(amended, parts, 'R01')

    def test_transport_success_and_meta_hash_are_required(self):
        descriptor, _, parts = self.build()
        response = {'Status': 'Success', 'ResponseCode': 0, 'StandardErrorContent': '',
                    'StandardOutputContent': export.DESCRIPTOR_PREFIX + export.encoded_json(descriptor).decode() + '\n'}
        self.assertEqual(export.parse_invocation(response, 'R01', 'descriptor'), descriptor)
        for changed in ({'Status': 'InProgress'}, {'ResponseCode': 1},
                        {'StandardErrorContent': 'synthetic-error'},
                        {'StandardOutputContent': response['StandardOutputContent'] + 'extra\n'}):
            with self.assertRaises(ValueError):
                export.parse_invocation({**response, **changed}, 'R01', 'descriptor')
        raw = parts[0].encode()
        meta = {'tag': 'R01', 'part': 0, 'chars': len(raw), 'sha256': export.digest(raw)}
        response['StandardOutputContent'] = export.PART_META_PREFIX + json.dumps(meta) + '\n' + export.PART_PREFIX + parts[0] + '\n'
        self.assertEqual(export.parse_invocation(response, 'R01', 'part', 0), raw)
        with self.assertRaises(ValueError):
            export.parse_invocation(response, 'R01', 'part', 1)

    def test_part_script_stdout_has_bounded_payload_and_compiles(self):
        script = export.part_command('R01', 17)
        self.assertIn('/opt/pg-lab/export/R01/part-0017.b64', script)
        self.assertIn('0<len(b)<=20000', script)
        compile(script.split("<<'PY'\n", 1)[1].rsplit('\nPY\n', 1)[0], '<remote-part>', 'exec')

    def test_multiple_parts_reassemble_in_order_and_reordered_parts_fail(self):
        data = {'observations': [export.digest(str(index).encode()) for index in range(1000)]}
        (self.root / 'evidence/large-valid.json').write_bytes(export.encoded_json(data))
        descriptor, _, parts = self.build()
        self.assertGreater(len(parts), 1)
        self.assertTrue(all(len(part) <= 20000 for part in parts))
        raw_parts = [part.encode('ascii') for part in parts]
        records, _ = export.verify_bundle(descriptor, raw_parts, 'R01')
        self.assertEqual(len(records), 3)
        with self.assertRaises(ValueError):
            export.verify_bundle(descriptor, list(reversed(raw_parts)), 'R01')

    def test_prepare_generates_self_contained_bounded_remote_script_without_aws(self):
        destination = Path(self.temp.name) / 'prepared'
        arguments = ['export_evidence.py', 'prepare', '--tag', 'R01',
                     '--directory', str(destination)]
        with mock.patch.object(export.sys, 'argv', arguments), mock.patch('builtins.print'):
            self.assertEqual(export.main(), 0)
        script = (destination / 'build.sh').read_text(encoding='utf-8')
        self.assertLess(len(script.encode()), 50000)
        self.assertTrue(script.startswith("PG_LAB_RUN_IDS="))
        self.assertIn(" python3 - remote-build --tag R01 <<'PG_LAB_EXPORT_PY'", script)
        embedded = script.split("<<'PG_LAB_EXPORT_PY'\n", 1)[1].rsplit('\nPG_LAB_EXPORT_PY\n', 1)[0]
        compile(embedded, '<remote-build>', 'exec')
        with mock.patch.object(export.sys, 'argv', arguments), mock.patch('builtins.print'):
            with self.assertRaises(FileExistsError):
                export.main()


if __name__ == '__main__':
    unittest.main()
