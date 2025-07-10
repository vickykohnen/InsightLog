DEFAULT_NGINX = {
    'type': 'web0',
    'dir_path': '/var/log/nginx/',
    'accesslog_filename': 'access.log',
    'errorlog_filename': 'error.log',
    'dateminutes_format': '[%d/%b/%Y:%H:%M',
    'datehours_format': '[%d/%b/%Y:%H',
    'datedays_format': '[%d/%b/%Y',
    'request_model': (r'(\d+\.\d+\.\d+\.\d+)\s-\s-\s'
                      r'\[(.+)\]\s'
                      r'"?(\w+)\s(.+)\s\w+/.+"'
                      r'\s(\d+)\s'
                      r'\d+\s"(.+)"\s'
                      r'"(.+)"'),
    'date_pattern': r'(\d+)/(\w+)/(\d+):(\d+):(\d+):(\d+)',
    'date_keys': {'day': 0, 'month': 1, 'year': 2, 'hour': 3, 'minute': 4, 'second': 5}
}


DEFAULT_APACHE2 = {
    'type': 'web0',
    'dir_path': '/var/log/apache2/',
    'accesslog_filename': 'access.log',
    'errorlog_filename': 'error.log',
    'dateminutes_format': '[%d/%b/%Y:%H:%M',
    'datehours_format': '[%d/%b/%Y:%H',
    'datedays_format': '[%d/%b/%Y',
    'request_model': (r'(\d+\.\d+\.\d+\.\d+)\s-\s-\s'
                      r'\[(.+)\]\s'
                      r'"?(\w+)\s(.+)\s\w+/.+"'
                      r'\s(\d+)\s'
                      r'\d+\s"(.+)"\s'
                      r'"(.+)"'),
    'date_pattern': r'(\d+)/(\w+)/(\d+):(\d+):(\d+):(\d+)',
    'date_keys': {'day': 0, 'month': 1, 'year': 2, 'hour': 3, 'minute': 4, 'second': 5}
}


DEFAULT_AUTH = {
    'type': 'auth',
    'dir_path': '/var/log/',
    'accesslog_filename': 'auth.log',
    'dateminutes_format': '%b %e %H:%M:',
    'datehours_format': '%b %e %H:',
    'datedays_format': '%b %e ',
    'request_model': (r'(\w+\s\s\d+\s\d+:\d+:\d+)\s'
                      r'\w+\s(\w+)\[\d+\]:\s'
                      r'(.+)'),
    'date_pattern': r'(\w+)\s(\s\d+|\d+)\s(\d+):(\d+):(\d+)',
    'date_keys': {'month': 0, 'day': 1, 'hour': 2, 'minute': 3, 'second': 4}
}


SERVICES_SWITCHER = {
    'nginx': DEFAULT_NGINX,
    'apache2': DEFAULT_APACHE2,
    'auth': DEFAULT_AUTH
}

IPv4_REGEX = r'(\d+.\d+.\d+.\d+)'
AUTH_USER_INVALID_USER = r'(?i)invalid\suser\s(\w+)\s'
AUTH_PASS_INVALID_USER = r'(?i)failed\spassword\sfor\s(\w+)\s'
