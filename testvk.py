from insightlog.lib import InsightLogAnalyzer
import os

# nginx_settings = get_service_settings('nginx')
# date_filter = get_date_filter(nginx_settings, '*', '*', 27, 4, 2016)
# base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

base_dir = "/Users/vicky/Documents/Projects/InsightLog"
file_name = os.path.join(base_dir, 'logs-samples/nginx1.sample')
print(file_name)

data = filter_data('192.168.5', filepath=file_name)
# data = filter_data(date_filter, data=data)