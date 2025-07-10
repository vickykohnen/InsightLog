def is_valid_year(year):
    """
    Check if year's value is valid
    :param year: int
    :return: boolean
    """
    return 2030 >= year > 1970


def is_valid_month(month):
    """
    Check if month's value is valid
    :param month: int
    :return: boolean
    """
    return 12 >= month > 0


def is_valid_day(day):
    """
    Check if day value is valid
    :param day: int
    :return: boolean
    """
    return 31 >= day > 0


def is_valid_hour(hour):
    """
    Check if hour value is valid
    :param hour: int|string
    :return: boolean
    """
    return (hour == '*') or (23 >= hour >= 0)


def is_valid_minute(minute):
    """
    Check if minute value is valid
    :param minute: int|string
    :return: boolean
    """
    return (minute == '*') or (59 >= minute >= 0)


