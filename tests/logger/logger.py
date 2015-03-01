'''
Created on Mar 12, 2014

@author: SK
self.logger = Logger(self.__class__.__name__).get()
'''
import os
import sys
import logging.handlers


class Logger(object):

    def __init__(self, name):
        name = name.replace('.log', '')
        logger = logging.getLogger('gglsbl3.%s' % name)
        logger.setLevel(logging.DEBUG)
        if not logger.handlers:
            # ensure logging dir exists
            logging_dir = "./"
            ensure_dir(logging_dir)
            file_name = os.path.join(logging_dir, '%s.log' % name)
            handler = logging.handlers.TimedRotatingFileHandler(file_name)
            formatter = logging.Formatter('%(levelname)s --#-- %(asctime)s --#-- %(name)s --#-- %(pathname)s --#-- %(filename)s --#-- %(module)s --#-- %(funcName)s --#-- Line %(lineno)d --#-- %(process)d --#-- %(processName)s --#-- %(thread)d --#-- %(threadName)s --#-- %(message)s')
            handler.setFormatter(formatter)
            handler.setLevel(logging.DEBUG)
            logger.addHandler(handler)
            ch = logging.StreamHandler(sys.stdout)
            ch.setLevel(logging.DEBUG)
            formatter = logging.Formatter('%(levelname)s: %(message)s - %(filename)s:%(lineno)d')
            ch.setFormatter(formatter)
            logger.addHandler(ch)
        self._logger = logger

    def get(self):
        return self._logger


def ensure_dir(directory):  # FIXME: Duplicate from utils here because of circular dependencies!
    if not os.path.exists(directory):
        os.makedirs(directory)
    if not os.path.exists(directory):
        raise Exception("Something went wrong during DIR creation")
