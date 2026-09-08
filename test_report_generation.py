import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scanner import SiteObservation
from summary_report import write_report


class ReportGenerationTests(unittest.TestCase):
    def test_cross_validation_and_masked_credential_summary_are_rendered(self):
        observation = SiteObservation(url='https://example.test/', status='200')
        observation.claim = {'confirmed': False}
        observation.external_osint = {
            'collection_status': {'shodan_internetdb': '수집 완료(1건)', 'censys': '수집 완료(1건)',
                                  'urlscan': '수집 완료(0건)'},
            'cross_validation': [{
                'ip': '8.8.8.8', 'providers': ['shodan', 'censys'],
                'ports_by_provider': {'shodan': [443], 'censys': [443]},
                'agreement': '2개 출처 일치', 'current_dns_match': True,
            }],
            'censys': [{
                'ip': '8.8.8.8', 'observed_at': '2026-09-08T00:00:00Z',
                'ports': [443], 'hostnames': ['example.test'], 'products': ['HTTPS'],
            }],
            'credential_exposure': {
                'status': 'collected', 'records_seen': 1, 'unique_accounts': 1,
                'privileged_count': 1, 'privileged_candidates': ['a***@example.test'],
            },
        }
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'report.md'
            write_report(path, [], observation, [], [], 0, False)
            report = path.read_text(encoding='utf-8')
            self.assertIn('### Censys 관측', report)
            self.assertIn('### Shodan·Censys IP·포트 교차 일치', report)
            self.assertIn('| 8.8.8.8 | 예 | Shodan | 443 |', report)
            self.assertIn('|  |  | Censys | 443 |', report)
            self.assertIn('|  |  | 통합 | 공통: 443 |', report)
            self.assertIn('a&#42;&#42;&#42;@example.test', report)
            self.assertNotIn('admin@example.test', report)

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
