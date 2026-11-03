"""Read a bound CloudWatch stream to a fixed cutoff; incomplete evidence fails closed.

GetLogEvents may return empty pages before later events. Only a repeated forward
token proves the pagination end. Reference: AWS GetLogEvents API documentation.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'control'))
from aws_context import CONFIG, ACCOUNT, PROFILE, STACK, RUN, TEST_RUN, MAIN_STACK_ARN, binding_value, load_context, require
import argparse
from datetime import datetime, timezone
import json
import re
import sys
ERROR_PATTERN = re.compile('\\]\\s*[EF]\\s*:|\\[E\\]|\\[F\\]|\\bERROR\\b|\\bFATAL\\b', re.I)
MAX_PAGES = 20
MAX_EVENTS = 10000

def collect_pages(logs, group, stream, start_time_ms, end_time_ms, max_pages=MAX_PAGES, max_events=MAX_EVENTS):
    """Read complete pages within hard bounds; never expose pagination tokens."""
    if not 1 <= max_pages <= MAX_PAGES or not 1 <= max_events <= MAX_EVENTS:
        raise ValueError('Invalid explicit log-collection bound')
    if not isinstance(start_time_ms, int) or not isinstance(end_time_ms, int) or (not 0 <= start_time_ms < end_time_ms):
        raise ValueError('Log collection requires an explicit nonempty bounded interval')
    events, token = ([], None)
    report = {'start_time_ms': start_time_ms, 'end_time_ms': end_time_ms, 'window_end_exclusive': True, 'pagination_complete': False, 'pages_requested': 0, 'max_pages': max_pages, 'max_events': max_events, 'completion_reason': None, 'incomplete_reason': None}
    for _ in range(max_pages):
        remaining = max_events - len(events)
        if remaining <= 0:
            report['incomplete_reason'] = 'event_limit_before_repeated_token'
            break
        request = {'logGroupName': group, 'logStreamName': stream, 'startTime': start_time_ms, 'endTime': end_time_ms, 'startFromHead': True, 'limit': remaining}
        if token is not None:
            request['nextToken'] = token
        report['pages_requested'] += 1
        try:
            result = logs.get_log_events(**request)
        except Exception as error:
            report['incomplete_reason'] = 'api_error'
            report['exception_type'] = type(error).__name__
            error_response = getattr(error, 'response', None)
            if isinstance(error_response, dict) and isinstance(error_response.get('Error'), dict):
                error_code = error_response['Error'].get('Code')
                if isinstance(error_code, str) and re.fullmatch('[A-Za-z][A-Za-z0-9_.-]{0,79}', error_code):
                    report['aws_error_code'] = error_code
            break
        if not isinstance(result, dict) or not isinstance(result.get('events'), list):
            report['incomplete_reason'] = 'missing_or_invalid_events'
            break
        page = result['events']
        if any((not isinstance(event, dict) or not isinstance(event.get('message'), str) or (not isinstance(event.get('timestamp'), int)) for event in page)):
            report['incomplete_reason'] = 'invalid_event_shape'
            break
        events.extend(page[:remaining])
        if len(page) > remaining:
            report['incomplete_reason'] = 'response_exceeded_event_limit'
            break
        if any((not start_time_ms <= event['timestamp'] < end_time_ms for event in page)):
            report['incomplete_reason'] = 'response_outside_fixed_interval'
            break
        new_token = result.get('nextForwardToken')
        if not isinstance(new_token, str) or not new_token:
            report['incomplete_reason'] = 'missing_or_invalid_forward_token'
            break
        if new_token == token:
            report['pagination_complete'] = True
            report['completion_reason'] = 'repeated_forward_token'
            break
        token = new_token
    else:
        report['incomplete_reason'] = 'page_limit_before_repeated_token'
    report['events'] = events
    report['event_count'] = len(events)
    report['error_candidates'] = [event for event in events if ERROR_PATTERN.search(event['message'])]
    return report

def main():
    started = datetime.now(timezone.utc)
    end_time_ms = int(started.timestamp() * 1000)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--label', required=True)
    parser.add_argument('--since', required=True)
    args = parser.parse_args()
    since = datetime.fromisoformat(args.since.replace('Z', '+00:00'))
    if since.tzinfo is None:
        raise ValueError('--since requires an explicit UTC offset')
    start_time_ms = int(since.timestamp() * 1000)
    if not 0 <= start_time_ms < end_time_ms:
        raise ValueError('--since must precede the fixed collection cutoff')
    from aws_context import client, save, stamp
    from dms_runtime import binding
    _, _, task = binding()
    settings = json.loads(task['ReplicationTaskSettings'])
    logging = settings['Logging']
    group, stream = (logging.get('CloudWatchLogGroup'), logging.get('CloudWatchLogStream'))
    if not isinstance(group, str) or not group.startswith('dms-tasks-') or (not isinstance(stream, str)) or (not stream.startswith('dms-task-')):
        raise ValueError('Task has no valid effective DMS log group/stream')
    report = collect_pages(client('logs'), group, stream, start_time_ms, end_time_ms)
    report.update(time=stamp(), collection_started_at_utc=started.isoformat(), task_arn=task['ReplicationTaskArn'], group=group, stream=stream)
    save(args.label + '-logs.json', report)
    print(json.dumps({key: report[key] for key in ('event_count', 'group', 'stream', 'error_candidates', 'pagination_complete', 'start_time_ms', 'end_time_ms', 'pages_requested', 'incomplete_reason')}, ensure_ascii=False))
    return 0 if report['pagination_complete'] else 2
if __name__ == '__main__':
    sys.exit(main())
