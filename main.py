import argparse
from insightlog.lib import InsightLogAnalyzer


def main():
    parser = argparse.ArgumentParser(description="Analyze server log files (nginx, apache2, auth)")
    parser.add_argument('--service', required=True, choices=['nginx', 'apache2', 'auth'], help='Type of log to analyze')
    parser.add_argument('--logfile', required=True, help='Path to the log file')
    parser.add_argument('--filter', required=False, default=None, help='String to filter log lines')
    args = parser.parse_args()

    analyzer = InsightLogAnalyzer(args.service, filepath=args.logfile)
    if args.filter:
        analyzer.add_filter(args.filter)
    requests = analyzer.get_requests()
    for req in requests:
        print(req)

if __name__ == '__main__':
    main() 