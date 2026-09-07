import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scanner import SiteObservation
from summary_report import write_report


class ReportGenerationTests(unittest.TestCase):
    def test_site_only_history_and_photo_guides(self):
        observation = SiteObservation(url='https://example.test/', status='error')
        observation.claim = {'confirmed': True}
        observation.historical_asm = {
            'domain': 'example.test',
            'urls': [{'timestamp': '20200101000000', 'source': 'wayback',
                      'category': 'admin', 'path': '/admin.asp'}],
            'timeline': [
                {'timestamp': '20200101000000', 'source': 'wayback', 'event': '과거 admin 경로: /admin.asp'},
                {'timestamp': '20210101000000', 'source': 'wayback', 'event': '과거 admin 경로: /admin.asp'},
            ],
        }
        with TemporaryDirectory() as directory:
            for verification in (False, True):
                path = Path(directory) / f'{verification}.md'
                write_report(path, [], observation, [], [], 0, False, verification)
                report = path.read_text(encoding='utf-8')
                self.assertNotIn('외부 포럼 공유 확인', report)
                self.assertNotIn('/로그인-경로', report)
                self.assertNotIn('수동 검증 기록표', report)
                timeline = report.split('### 과거 자산 시간축')[1]
                self.assertEqual(timeline.count('관리 기능 잔존'), 2)
                self.assertIn('2020-01-01 00:00:00 UTC', report)
                self.assertIn('조사 이유 · 예상 위험', report)
                self.assertEqual('Win + Shift + S' in report, verification)


if __name__ == '__main__':
    unittest.main()
