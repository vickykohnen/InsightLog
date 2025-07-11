import argparse
from insightlog.lib import InsightLogAnalyzer


def main():
    parser = argparse.ArgumentParser(description="Analyze server log files (nginx, apache2, auth)")
    parser.add_argument('--service', required=True, choices=['nginx', 'apache2', 'auth'], help='Type of log to analyze')
    parser.add_argument('--logfile', required=True, help='Path to the log file')
    parser.add_argument('--filter', required=False, default=None, help='String to filter log lines')
    parser.add_argument('--filtererror', action='store_true', help='Only show logs with error status codes')

    args = parser.parse_args()

    analyzer = InsightLogAnalyzer(args.service, filepath=args.logfile)
    if args.filter:
        analyzer.add_filter(args.filter)
    requests = analyzer.get_requests()
    if args.filtererror:
        def is_error(entry):
            try:
                code = int(entry.get("CODE", 0))
                return not (200 <= code < 300)
            except (ValueError, TypeError):
                return True

        requests = [req for req in requests if is_error(req)]

    for req in requests:
        print(req)

if __name__ == '__main__':
    main() 