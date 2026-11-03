"""Local regression tests using synthetic pages; no AWS imports or calls."""
import json
import unittest
from collect_dms_logs import ERROR_PATTERN, collect_pages


def event(message, timestamp=1500):
    return {'timestamp': timestamp, 'message': message, 'ingestionTime': 1600}


class FakeLogs:
    def __init__(self, pages):
        self.pages = iter(pages)
        self.requests = []

    def get_log_events(self, **request):
        self.requests.append(request)
        response = next(self.pages)
        if isinstance(response, Exception):
            raise response
        return response


class CollectorTests(unittest.TestCase):
    def test_native_and_legacy_error_formats(self):
        for message in ('[TARGET_APPLY ]E: RetCode: SQL_ERROR', '[VALIDATOR ]F: stopped',
                        '[E] problem', '[F] problem', 'ERROR occurred', 'FATAL failure'):
            with self.subTest(message=message):
                self.assertIsNotNone(ERROR_PATTERN.search(message))
        for message in ('[SOURCE ]I: healthy', '[SOURCE ]W: pending', 'errors=0', 'error_count=0'):
            with self.subTest(message=message):
                self.assertIsNone(ERROR_PATTERN.search(message))

    def test_empty_changed_token_does_not_hide_later_error(self):
        error = event('[TARGET_APPLY ]E: RetCode: SQL_ERROR')
        logs = FakeLogs([{'events': [], 'nextForwardToken': 'a'},
                         {'events': [], 'nextForwardToken': 'b'},
                         {'events': [error], 'nextForwardToken': 'c'},
                         {'events': [], 'nextForwardToken': 'c'}])
        result = collect_pages(logs, 'group', 'stream', 1000, 2000)
        self.assertTrue(result['pagination_complete'])
        self.assertEqual(result['events'], [error])
        self.assertEqual(result['error_candidates'], [error])
        self.assertEqual(len(logs.requests), 4)
        self.assertEqual([request.get('nextToken') for request in logs.requests], [None, 'a', 'b', 'c'])
        self.assertTrue(all(request['endTime'] == 2000 and request['startFromHead'] for request in logs.requests))
        self.assertEqual(result['end_time_ms'], 2000)

    def test_partial_nonempty_pages_are_all_preserved(self):
        first, second = event('[SOURCE ]I: first'), event('[SOURCE ]I: second')
        logs = FakeLogs([{'events': [first], 'nextForwardToken': 'a'},
                         {'events': [second], 'nextForwardToken': 'b'},
                         {'events': [], 'nextForwardToken': 'b'}])
        result = collect_pages(logs, 'group', 'stream', 1000, 2000)
        self.assertTrue(result['pagination_complete'])
        self.assertEqual(result['events'], [first, second])
        self.assertEqual(result['error_candidates'], [])

    def test_page_bound_fails_closed_even_on_empty_pages(self):
        logs = FakeLogs([{'events': [], 'nextForwardToken': 'a'},
                         {'events': [], 'nextForwardToken': 'b'}])
        result = collect_pages(logs, 'group', 'stream', 1000, 2000, max_pages=2)
        self.assertFalse(result['pagination_complete'])
        self.assertEqual(result['incomplete_reason'], 'page_limit_before_repeated_token')
        self.assertEqual(len(logs.requests), 2)

    def test_event_bound_fails_closed_until_end_token_is_known(self):
        logs = FakeLogs([{'events': [event('one'), event('two')], 'nextForwardToken': 'a'}])
        result = collect_pages(logs, 'group', 'stream', 1000, 2000, max_events=2)
        self.assertFalse(result['pagination_complete'])
        self.assertEqual(result['event_count'], 2)
        self.assertEqual(result['incomplete_reason'], 'event_limit_before_repeated_token')
        self.assertEqual(len(logs.requests), 1)

    def test_missing_token_is_not_end_of_stream(self):
        logs = FakeLogs([{'events': []}])
        result = collect_pages(logs, 'group', 'stream', 1000, 2000)
        self.assertFalse(result['pagination_complete'])
        self.assertEqual(result['incomplete_reason'], 'missing_or_invalid_forward_token')

    def test_api_failure_preserves_partial_events_without_exception_text(self):
        first = event('[SOURCE ]I: first')
        logs = FakeLogs([{'events': [first], 'nextForwardToken': 'a'}, RuntimeError('fixture-private-error-text')])
        result = collect_pages(logs, 'group', 'stream', 1000, 2000)
        self.assertFalse(result['pagination_complete'])
        self.assertEqual(result['events'], [first])
        self.assertEqual(result['incomplete_reason'], 'api_error')
        self.assertEqual(result['exception_type'], 'RuntimeError')
        self.assertNotIn('fixture-private-error-text', json.dumps(result))

    def test_future_or_malformed_page_fails_closed(self):
        for page in ({'events': [event('future', 2000)], 'nextForwardToken': 'a'},
                     {'events': [{'message': 'missing timestamp'}], 'nextForwardToken': 'a'},
                     {'nextForwardToken': 'a'}):
            with self.subTest(page=page):
                result = collect_pages(FakeLogs([page]), 'group', 'stream', 1000, 2000)
                self.assertFalse(result['pagination_complete'])


if __name__ == '__main__':
    unittest.main()
