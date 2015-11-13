'''
Created on May 7, 2015

@author: sk
'''

def prettify_seconds(seconds):
    """
    Prettifies seconds.
    Takes number of seconds (int) as input and returns a prettified string.

    Example:
    >>> prettify_seconds(342543)
    '3 days, 23 hours, 9 minutes and 3 seconds'
    """
    if seconds < 0:
        raise Exception("negative input not allowed")
    signs = {"s": {"singular": "second", "plural": "seconds", },
             "h": {"singular": "hour", "plural": "hours"},
             "min": {"singular": "minute", "plural": "minutes"},
             "d": {"singular": "day", "plural": "days"}
            }
    seperator = ", "
    last_seperator = " and "

    def get_sign(unit, value):
        if value == 1 or value == -1:
            return signs[unit]["singular"]
        else:
            return signs[unit]["plural"]

    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    daystext = "{} {}".format(days, get_sign("d", days)) if days else ""
    hourstext = "{} {}".format(hours, get_sign("h", hours)) if hours else ""
    minutestext = "{} {}".format(minutes, get_sign("min", minutes)) if minutes else ""
    if (not seconds) and (days or hours or minutes):
        secondstext = ""
    else:
        secondstext = "{} {}".format(seconds, get_sign("s", seconds))
    output_list = [daystext, hourstext, minutestext, secondstext]
    filtered = list(filter(None, output_list))
    if len(filtered) <= 2:
        output = last_seperator.join(filtered)
    else:
        output = seperator.join(filtered[:-1]) + last_seperator + filtered[-1]
    return output

def format_max_len(string_to_format, max_len=15, replace="[...]"):
    """
    Formats a string so len(format_max_length(string_to_format)) <= max_len
    If the string_to_format is longer than max_len, it replaces characters in the middle with [...]

    Example:
    >>> util.format_max_len('abcdefghijklmnopqrstuvwxyz')
    'abcde[...]vwxyz'
    """
    real_max_len = max_len-len(replace)  # needed to count the [...] in the ouput length
    if len(string_to_format) <= max_len:
        return string_to_format
    first = real_max_len // 2  # Insert the [...] in the (floored) middle
    last = real_max_len - first
    return string_to_format[0:first] + replace + string_to_format[len(string_to_format) - last:]
