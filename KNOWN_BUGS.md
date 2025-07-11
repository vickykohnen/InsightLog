# Known Bugs and Replication Steps

## 1. remove_filter does not remove by index
- **How to replicate:**
  - Create an analyzer, add three filters: 'a', 'b', 'c'.
  - Call `remove_filter(1)`.
  - Instead of removing the second filter, it may raise a ValueError or remove the wrong filter.

## 2. filter_data returns None on error instead of raising
- **How to replicate:**
  - Call `filter_data` with a non-existent file path.
  - Instead of raising an exception, it prints the error and returns None.

## 3. get_web_requests output format inconsistent with get_auth_requests
- **How to replicate:**
  - Use `get_requests()` for both a web log and an auth log.
  - Compare the output dictionaries: keys and order differ.

## 4. No handling for empty files
- **How to replicate:**
  - Run analyzer on an empty log file.
  - Returns empty list, but no warning or message is shown.

## 5. No handling for malformed log lines
- **How to replicate:**
  - Add a malformed line to a log file (e.g., missing fields).
  - Analyzer silently skips it; should log or count malformed lines.

## 6. No check for file encoding
- **How to replicate:**
  - Try to analyze a log file with non-UTF-8 encoding.
  - May crash with a UnicodeDecodeError.

## 7. Large files are read into memory at once (performance issue)
- **How to replicate:**
  - Analyze a very large log file (hundreds of MBs or more).
  - May cause high memory usage or crash. 

## 8. There is no Exception/Error handling in file_all when Opening the file
  - Add a Try / Except structure and include the following Except errors:
    -FileNotFoundError                                                                    
    -IOError
    -EnvironmentError
  - For these exceptions, log and raise an error  