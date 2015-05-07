'''
Created on May 7, 2015

@author: sk
'''


def prettify_seconds(seconds):
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
