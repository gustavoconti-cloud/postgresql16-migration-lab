"""Export only lab JSON evidence; AWS submission remains with the operator.

prepare -> SSM submit build.sh -> read descriptor -> SSM submit part scripts
-> read each part -> finish. AWS imports occur only in the read command.
"""
import argparse
import base64
from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import shlex
import sys


MAX_FILE = 1024 * 1024
MAX_TOTAL = 20 * MAX_FILE
MAX_BUNDLE = 128 * MAX_FILE
PART_CHARS = 20000
MAX_FILES = 10000
def configured_state_paths():
    if str(globals().get('__file__', '')) == '<stdin>':
        values = json.loads(os.environ.get('PG_LAB_RUN_IDS', '[]'))
    else:
        from aws_context import CONFIG
        values = CONFIG.get('evidence_run_ids', [])
    if not isinstance(values, list) or len(values) > 2 or any(not isinstance(x, str) or re.fullmatch(r'[A-Za-z0-9-]{3,64}', x) is None for x in values):
        raise ValueError('invalid_explicit_evidence_run_ids')
    return tuple('state/' + x + '.json' for x in values)
STATE_PATHS = configured_state_paths()
SECRET_KEYS = frozenset(('password', 'passwd', 'secretstring', 'secretbinary',
    'secretaccesskey', 'sessiontoken', 'accesstoken', 'refreshtoken', 'idtoken',
    'apikey', 'accesskeyid', 'authorization', 'privatekey', 'clientsecret',
    'awsaccesskeyid', 'awssecretaccesskey', 'awssessiontoken', 'credentials'))
SECRET_VALUE = re.compile(r'(?:AKIA|ASIA)[A-Z0-9]{16}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|SCRAM-SHA-256\$[0-9]+:')
HEX = re.compile(r'[0-9a-f]{64}\Z')
DESCRIPTOR_PREFIX = 'LAB_EXPORT_DESCRIPTOR='
PART_PREFIX = 'LAB_EXPORT_PART_BASE64='
PART_META_PREFIX = 'LAB_EXPORT_PART_META='
ACL_FIELDS = frozenset(('acl', 'database_acl', 'schema_acl', 'table_acl'))
ACL_ROLE = '(?:postgres|lab_admin|pg_database_owner|dms_source|dms_target|lab_reader_source|lab_reader_target|lab_writer_source|lab_writer_target)'
ACL_ITEM = f'(?:{ACL_ROLE})?=(?:[arwdDxtUCTcXsA]\\*?)*/{ACL_ROLE}'
PG_ACL_ARRAY = re.compile(r'\{(?:' + ACL_ITEM + r'(?:,' + ACL_ITEM + r')*)?\}\Z')
REASON_CODES = frozenset('''bundle_binding_mismatch bundle_hash_mismatch bundle_size_limit
    case_colliding_path descriptor_binding_mismatch descriptor_transport_invalid
    directory_or_symlink_refused duplicate_json_key duplicate_or_invalid_file_record
    existing_output_refused file_count_limit file_hash_or_size_mismatch
    file_or_symlink_refused file_size_or_type_refused invalid_command_id
    invalid_descriptor_bound invalid_descriptor_hash invalid_file_record invalid_part_binding
    invalid_part_count invalid_relative_path invalid_tag json_depth_limit
    local_readback_mismatch missing_transport_parts no_evidence_files
    part_binding_or_hash_mismatch part_transport_invalid path_outside_allowlist
    required_ledger_missing required_snapshot_files_missing secret_key_refused
    secret_value_refused source_byte_count_mismatch source_changed_during_read
    source_symlink_refused ssm_command_not_successful ssm_script_size_limit
    ssm_target_binding_mismatch total_size_limit truncated_or_oversized_part
    uncompressed_hash_mismatch unexpected_part_index unsafe_path_component
    unsafe_relative_path invalid_nested_json_refused invalid_json_constant'''.split())


def require(condition, code):
    if not condition:
        raise ValueError(code)


def safe_failure(error):
    """Only fixed codes and a previously validated relative path may leave stdout."""
    reason = 'unclassified_error'
    if isinstance(error, json.JSONDecodeError):
        reason = 'invalid_json_syntax'
    elif isinstance(error, UnicodeError):
        reason = 'invalid_utf8'
    elif isinstance(error, FileExistsError):
        reason = 'existing_output_refused'
    elif isinstance(error, FileNotFoundError):
        reason = 'file_missing'
    elif isinstance(error, PermissionError):
        reason = 'permission_denied'
    elif len(error.args) == 1 and isinstance(error.args[0], str) and error.args[0] in REASON_CODES:
        reason = error.args[0]
    result = {'success': False, 'failure_class': 'export_refused',
              'exception_type': type(error).__name__, 'reason_code': reason}
    relative = getattr(error, '_export_relative_path', None)
    if relative is not None:
        try:
            result['relative_path'] = allowed_path(relative)
        except Exception:
            pass
    return result


def digest(value):
    return hashlib.sha256(value).hexdigest()


def utc():
    return datetime.now(timezone.utc).isoformat()


def encoded_json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def parse_json(raw):
    def invalid_constant(_):
        raise ValueError('invalid_json_constant')
    def unique_keys(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate_json_key')
            result[key] = value
        return result
    return json.loads(raw.decode('utf-8'), parse_constant=invalid_constant,
                      object_pairs_hook=unique_keys)


def reject_secrets(value, depth=0, field_name=None):
    require(depth < 100, 'json_depth_limit')
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = re.sub(r'[^a-z0-9]', '', key.lower())
            require(normalized not in SECRET_KEYS, 'secret_key_refused')
            reject_secrets(item, depth + 1, field_name=key)
    elif isinstance(value, list):
        for item in value:
            reject_secrets(item, depth + 1, field_name=field_name)
    elif isinstance(value, str):
        require(SECRET_VALUE.search(value) is None, 'secret_value_refused')
        # datacl/nspacl/relacl::text are PostgreSQL arrays, not serialized JSON.
        # Only these typed fields and the complete closed-role ACL grammar qualify.
        if field_name in ACL_FIELDS and PG_ACL_ARRAY.fullmatch(value):
            return
        nested = value.lstrip()
        if nested.startswith(('{', '[')):
            try:
                parsed = parse_json(value.encode('utf-8'))
            except (ValueError, UnicodeError):
                raise ValueError('invalid_nested_json_refused') from None
            reject_secrets(parsed, depth + 1)


def allowed_path(value):
    require(isinstance(value, str) and 0 < len(value) < 240,
            'invalid_relative_path')
    path = PurePosixPath(value)
    require(not path.is_absolute() and str(path) == value and
            '\\' not in value and ':' not in value, 'unsafe_relative_path')
    reserved = {'CON', 'PRN', 'AUX', 'NUL'} | {
        f'{prefix}{number}' for prefix in ('COM', 'LPT') for number in range(1, 10)}
    for part in path.parts:
        require(part not in ('.', '..') and not part.endswith(('.', ' ')) and
                not any(ord(char) < 32 for char in part) and
                not any(char in '<>"|?*' for char in part) and
                part.split('.')[0].upper() not in reserved, 'unsafe_path_component')
    require(value in STATE_PATHS or
            (len(path.parts) >= 2 and path.parts[0] == 'evidence' and
             value.endswith('.json')), 'path_outside_allowlist')
    return value


def regular_directory(path):
    for parent in (path, *path.parents):
        require(stat.S_ISDIR(parent.lstat().st_mode) and
                not getattr(parent, 'is_junction', lambda: False)(),
                'directory_or_symlink_refused')


def read_json_file(path):
    require(stat.S_ISREG(path.lstat().st_mode), 'file_or_symlink_refused')
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_BINARY', 0) |
                         getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(descriptor, 'rb') as handle:
        before = os.fstat(handle.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_FILE,
                'file_size_or_type_refused')
        raw = handle.read(MAX_FILE + 1)
        after = os.fstat(handle.fileno())
    require(len(raw) <= MAX_FILE and before.st_size == after.st_size == len(raw)
            and before.st_mtime_ns == after.st_mtime_ns, 'source_changed_during_read')
    parsed = parse_json(raw)
    reject_secrets(parsed)
    return raw


def contextual_json_file(path, relative):
    relative = allowed_path(relative)
    try:
        return read_json_file(path)
    except Exception as error:
        error._export_relative_path = relative
        raise


def build_snapshot(root, tag):
    require(tag in ('R01', 'R02'), 'invalid_tag')
    require(len(STATE_PATHS) == 2, 'set_two_explicit_evidence_run_ids')
    regular_directory(root)
    evidence = root / 'evidence'
    regular_directory(evidence)
    paths = []
    for current, dirs, names in os.walk(evidence, followlinks=False):
        for directory in dirs:
            regular_directory(Path(current) / directory)
        for name in names:
            candidate = Path(current) / name
            require(not candidate.is_symlink(), 'source_symlink_refused')
            if name.endswith('.json'):
                paths.append(candidate)
    require(bool(paths), 'no_evidence_files')
    regular_directory(root / 'state')
    for index, relative in enumerate(STATE_PATHS):
        candidate = root / relative
        if index == 0 or tag == 'R02':
            require(candidate.exists(), 'required_ledger_missing')
        if candidate.exists() or candidate.is_symlink():
            paths.append(candidate)
    require(len(paths) <= MAX_FILES, 'file_count_limit')
    records, seen, total = [], set(), 0
    for path in sorted(paths, key=lambda p: p.relative_to(root).as_posix()):
        relative = allowed_path(path.relative_to(root).as_posix())
        require(relative.casefold() not in seen, 'case_colliding_path')
        seen.add(relative.casefold())
        raw = contextual_json_file(path, relative)
        total += len(raw)
        require(total <= MAX_TOTAL, 'total_size_limit')
        records.append({'path': relative, 'sha256': digest(raw),
                        'bytes': len(raw), 'content_text': raw.decode('utf-8')})
    raw_bundle = encoded_json({'version': 1, 'tag': tag, 'files': records})
    require(len(raw_bundle) <= MAX_BUNDLE, 'bundle_size_limit')
    compressed = gzip.compress(raw_bundle, mtime=0)
    encoded = base64.b64encode(compressed).decode('ascii')
    parts = [encoded[offset:offset + PART_CHARS]
             for offset in range(0, len(encoded), PART_CHARS)]
    descriptor = {'version': 1, 'tag': tag, 'bundle_sha256': digest(compressed),
        'compressed_bytes': len(compressed), 'uncompressed_sha256': digest(raw_bundle),
        'uncompressed_bytes': len(raw_bundle), 'file_count': len(records),
        'source_bytes': total, 'part_count': len(parts), 'part_chars': PART_CHARS}
    return descriptor, compressed, parts


def exclusive_write(path, raw):
    with path.open('xb') as handle:
        handle.write(raw)


def remote_build(tag):
    root = Path('/opt/pg-lab')
    descriptor, compressed, parts = build_snapshot(root, tag)
    export = root / 'export'
    export.mkdir(mode=0o700, exist_ok=True)
    regular_directory(export)
    destination = export / tag
    destination.mkdir(mode=0o700, exist_ok=False)
    exclusive_write(destination / 'bundle.json.gz', compressed)
    for index, part in enumerate(parts):
        exclusive_write(destination / f'part-{index:04d}.b64', part.encode('ascii'))
    exclusive_write(destination / 'descriptor.json', encoded_json(descriptor))
    print(DESCRIPTOR_PREFIX + encoded_json(descriptor).decode('utf-8'))


def validate_descriptor(value, tag):
    fields = {'version', 'tag', 'bundle_sha256', 'compressed_bytes',
              'uncompressed_sha256', 'uncompressed_bytes', 'file_count',
              'source_bytes', 'part_count', 'part_chars'}
    require(isinstance(value, dict) and set(value) == fields and
            value['version'] == 1 and value['tag'] == tag,
            'descriptor_binding_mismatch')
    for key in ('bundle_sha256', 'uncompressed_sha256'):
        require(isinstance(value[key], str) and HEX.fullmatch(value[key]),
                'invalid_descriptor_hash')
    for key, cap in (('compressed_bytes', MAX_BUNDLE),
                     ('uncompressed_bytes', MAX_BUNDLE),
                     ('file_count', MAX_FILES), ('source_bytes', MAX_TOTAL),
                     ('part_count', (MAX_BUNDLE * 4 // 3 + PART_CHARS) // PART_CHARS)):
        require(type(value[key]) is int and 0 < value[key] <= cap,
                'invalid_descriptor_bound')
    expected_chars = 4 * ((value['compressed_bytes'] + 2) // 3)
    require(value['part_chars'] == PART_CHARS and value['part_count'] ==
            (expected_chars + PART_CHARS - 1) // PART_CHARS, 'invalid_part_count')
    return value


def part_command(tag, index):
    require(tag in ('R01', 'R02') and type(index) is int and 0 <= index < 10000,
            'invalid_part_binding')
    # Entire stdout stays below the SSM 24,000-character response limit.
    return ("python3 - <<'PY'\nimport hashlib,json,pathlib\n"
        f"p=pathlib.Path('/opt/pg-lab/export/{tag}/part-{index:04d}.b64')\n"
        "assert p.is_file() and not p.is_symlink()\nb=p.read_bytes()\n"
        "assert 0<len(b)<=20000\n"
        f"m={{'tag':{tag!r},'part':{index},'chars':len(b),'sha256':hashlib.sha256(b).hexdigest()}}\n"
        f"print({PART_META_PREFIX!r}+json.dumps(m,separators=(',',':')))\n"
        f"print({PART_PREFIX!r}+b.decode('ascii'))\nPY\n")


def parse_invocation(response, tag, kind, part=None):
    require(response.get('Status') == 'Success' and response.get('ResponseCode') == 0
            and response.get('StandardErrorContent', '') == '', 'ssm_command_not_successful')
    lines = response.get('StandardOutputContent', '').splitlines()
    if kind == 'descriptor':
        require(len(lines) == 1 and lines[0].startswith(DESCRIPTOR_PREFIX),
                'descriptor_transport_invalid')
        return validate_descriptor(parse_json(lines[0][len(DESCRIPTOR_PREFIX):].encode()), tag)
    require(len(lines) == 2 and lines[0].startswith(PART_META_PREFIX) and
            lines[1].startswith(PART_PREFIX), 'part_transport_invalid')
    meta = parse_json(lines[0][len(PART_META_PREFIX):].encode())
    raw = lines[1][len(PART_PREFIX):].encode('ascii')
    require(set(meta) == {'tag', 'part', 'chars', 'sha256'} and
            meta['tag'] == tag and meta['part'] == part and
            0 < len(raw) <= PART_CHARS and len(raw) % 4 == 0 and
            meta['chars'] == len(raw) and meta['sha256'] == digest(raw),
            'part_binding_or_hash_mismatch')
    base64.b64decode(raw, validate=True)
    return raw


def verify_bundle(descriptor, parts, tag):
    descriptor = validate_descriptor(descriptor, tag)
    require(len(parts) == descriptor['part_count'], 'missing_transport_parts')
    expected_chars = 4 * ((descriptor['compressed_bytes'] + 2) // 3)
    for index, part in enumerate(parts):
        expected = min(PART_CHARS, expected_chars - index * PART_CHARS)
        require(len(part) == expected, 'truncated_or_oversized_part')
    compressed = base64.b64decode(b''.join(parts), validate=True)
    require(len(compressed) == descriptor['compressed_bytes'] and
            digest(compressed) == descriptor['bundle_sha256'], 'bundle_hash_mismatch')
    with gzip.GzipFile(fileobj=io.BytesIO(compressed), mode='rb') as handle:
        raw = handle.read(descriptor['uncompressed_bytes'] + 1)
    require(len(raw) == descriptor['uncompressed_bytes'] and
            digest(raw) == descriptor['uncompressed_sha256'], 'uncompressed_hash_mismatch')
    bundle = parse_json(raw)
    require(isinstance(bundle, dict) and set(bundle) == {'version', 'tag', 'files'}
            and bundle['version'] == 1 and bundle['tag'] == tag and
            isinstance(bundle['files'], list) and
            len(bundle['files']) == descriptor['file_count'], 'bundle_binding_mismatch')
    records, seen, total = [], set(), 0
    for entry in bundle['files']:
        require(isinstance(entry, dict) and set(entry) ==
                {'path', 'sha256', 'bytes', 'content_text'}, 'invalid_file_record')
        relative = allowed_path(entry['path'])
        require(relative.casefold() not in seen and isinstance(entry['content_text'], str),
                'duplicate_or_invalid_file_record')
        seen.add(relative.casefold())
        content = entry['content_text'].encode('utf-8')
        require(type(entry['bytes']) is int and 0 < len(content) <= MAX_FILE and
                len(content) == entry['bytes'] and digest(content) == entry['sha256'],
                'file_hash_or_size_mismatch')
        reject_secrets(parse_json(content))
        total += len(content)
        records.append((relative, content))
    require(total == descriptor['source_bytes'] and total <= MAX_TOTAL,
            'source_byte_count_mismatch')
    names = {relative for relative, _ in records}
    require(STATE_PATHS[0] in names and (tag != 'R02' or STATE_PATHS[1] in names)
            and any(name.startswith('evidence/') for name in names),
            'required_snapshot_files_missing')
    return records, compressed


def finish(directory, tag):
    regular_directory(directory)
    descriptor = validate_descriptor(parse_json((directory / 'descriptor.json').read_bytes()), tag)
    parts = [(directory / f'part-{index:04d}.b64').read_bytes()
             for index in range(descriptor['part_count'])]
    records, compressed = verify_bundle(descriptor, parts, tag)
    destination = directory / 'files'
    require(all(not item.exists() and not item.is_symlink() for item in
                (destination, directory / 'verified-receipt.json',
                 directory / 'bundle.json.gz')), 'existing_output_refused')
    destination.mkdir(mode=0o700)
    for relative, content in records:
        path = destination / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        regular_directory(path.parent)
        exclusive_write(path, content)
    readbacks = []
    for relative, content in records:
        readback = read_json_file(destination / relative)
        require(readback == content, 'local_readback_mismatch')
        readbacks.append({'path': relative, 'bytes': len(readback), 'sha256': digest(readback)})
    exclusive_write(directory / 'bundle.json.gz', compressed)
    receipt = {'version': 1, 'tag': tag, 'verified_at_utc': utc(),
        'success': True, 'all_json_utf8_valid': True, 'secret_scan_passed': True,
        'allowlist_valid': True, 'all_file_hashes_verified': True,
        'bundle_sha256': descriptor['bundle_sha256'], 'file_count': len(records),
        'source_bytes': descriptor['source_bytes'], 'files': readbacks}
    exclusive_write(directory / 'verified-receipt.json', encoded_json(receipt))
    return receipt


def read_command(args):
    # Canonical account/region/instance validation; no SendCommand capability here.
    from aws_context import client
    from ssm_runtime import source_instance
    require(re.fullmatch(r'[0-9a-fA-F-]{36}', args.command_id), 'invalid_command_id')
    regular_directory(args.directory)
    instance_id = source_instance()
    response = client('ssm').get_command_invocation(CommandId=args.command_id,
                                                   InstanceId=instance_id)
    require(response.get('CommandId') == args.command_id and
            response.get('InstanceId') == instance_id, 'ssm_target_binding_mismatch')
    value = parse_invocation(response, args.tag, args.kind, args.part)
    if args.kind == 'descriptor':
        exclusive_write(args.directory / 'descriptor.json', encoded_json(value))
        commands = args.directory / 'commands'
        commands.mkdir()
        for index in range(value['part_count']):
            exclusive_write(commands / f'part-{index:04d}.sh', part_command(args.tag, index).encode())
        summary = {'success': True, 'tag': args.tag, 'part_count': value['part_count'],
                   'commands_directory': str(commands), 'bundle_sha256': value['bundle_sha256']}
    else:
        descriptor = validate_descriptor(parse_json((args.directory / 'descriptor.json').read_bytes()), args.tag)
        require(type(args.part) is int and 0 <= args.part < descriptor['part_count'],
                'unexpected_part_index')
        exclusive_write(args.directory / f'part-{args.part:04d}.b64', value)
        summary = {'success': True, 'tag': args.tag, 'part': args.part, 'chars': len(value)}
    receipt = {'time_utc': utc(), 'command_id': args.command_id,
               'instance_id': instance_id, 'kind': args.kind, 'part': args.part, **summary}
    suffix = 'descriptor' if args.kind == 'descriptor' else f'part-{args.part:04d}'
    exclusive_write(args.directory / f'{suffix}-transport-receipt.json', encoded_json(receipt))
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    for action in ('prepare', 'read', 'finish', 'remote-build'):
        command = sub.add_parser(action)
        command.add_argument('--tag', choices=('R01', 'R02'), required=True)
        if action != 'remote-build':
            command.add_argument('--directory', type=Path, required=True)
        if action == 'read':
            command.add_argument('--kind', choices=('descriptor', 'part'), required=True)
            command.add_argument('--command-id', required=True)
            command.add_argument('--part', type=int)
    args = parser.parse_args()
    if args.action == 'remote-build':
        remote_build(args.tag)
        return 0
    if args.action == 'prepare':
        args.directory.parent.mkdir(parents=True, exist_ok=True)
        regular_directory(args.directory.parent.resolve())
        args.directory.mkdir(exist_ok=False)
        source = Path(__file__).read_text(encoding='utf-8')
        command = "PG_LAB_RUN_IDS=" + shlex.quote(json.dumps([Path(x).stem for x in STATE_PATHS])) + " " + f"python3 - remote-build --tag {args.tag} <<'PG_LAB_EXPORT_PY'\n" + source + "\nPG_LAB_EXPORT_PY\n"
        require(len(command.encode()) < 50000, 'ssm_script_size_limit')
        exclusive_write(args.directory / 'build.sh', command.encode('utf-8'))
        result = {'success': True, 'tag': args.tag, 'build_command': str(args.directory / 'build.sh')}
    elif args.action == 'read':
        result = read_command(args)
    else:
        receipt = finish(args.directory, args.tag)
        result = {key: receipt[key] for key in ('success', 'tag', 'file_count', 'source_bytes', 'bundle_sha256')}
        result['receipt'] = str(args.directory / 'verified-receipt.json')
    print(json.dumps(result, ensure_ascii=True))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        # Do not expose file contents, SSM responses, credentials or tracebacks.
        print(json.dumps(safe_failure(error), ensure_ascii=True))
        raise SystemExit(2)
