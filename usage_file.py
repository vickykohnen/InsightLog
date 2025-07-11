from insightlog.lib import InsightLogAnalyzer

analyzer = InsightLogAnalyzer('nginx', filepath='logs-samples/nginx1.sample')
analyzer.add_filter('192.10.1.1')
requests = analyzer.get_requests()
print(requests)