'''
Created on Mar 12, 2014

@author: SK
self.logger = Logger(self.__class__.__name__).get()
'''
import os
import sys
import logging.handlers
import gglsbl3.settings.logger


class Logger(object):
    """
    Usage: self.logger = Logger(self.__class__.__name__).get()
           or log = Logger("somename").get()
    """
    def __init__(self, name):
        name = name.replace('.log', '')
        logger = logging.getLogger('gglsbl3.%s' % name)
        logger.setLevel(logging.DEBUG)
        if not logger.handlers:
            # ensure logging dir exists
            gglsbl3.settings.logger.LOG_DIR
            logging_dir = gglsbl3.settings.logger.LOG_DIR
            ensure_dir(logging_dir)
            file_name = os.path.join(logging_dir, '%s.log' % name)
            handler = logging.handlers.TimedRotatingFileHandler(file_name)
            formatter = logging.Formatter('%(levelname)s --#-- %(asctime)s --#-- %(name)s --#-- %(pathname)s --#-- %(filename)s --#-- %(module)s --#-- %(funcName)s --#-- Line %(lineno)d --#-- %(process)d --#-- %(processName)s --#-- %(thread)d --#-- %(threadName)s --#-- %(message)s')
            handler.setFormatter(formatter)
            handler.setLevel(gglsbl3.settings.logger.LOG_LEVEL_FILE)
            # logger.addHandler(handler)  # uncomment this to enable logging to file
            ch = logging.StreamHandler(sys.stdout)
            ch.setLevel(gglsbl3.settings.logger.LOG_LEVEL_CONSOLE)
            formatter = logging.Formatter('%(levelname)s: %(message)s - %(filename)s:%(lineno)d')
            ch.setFormatter(formatter)
            logger.addHandler(ch)
        self._logger = logger

    def get(self):
        return self._logger


def ensure_dir(directory):  # FIXME: Unfortunate duplicate from utils here because of circular dependencies!
    if not os.path.exists(directory):
        os.makedirs(directory)
    if not os.path.exists(directory):
        raise RuntimeError("Could not create dir: '{d}'".format(d=directory))
