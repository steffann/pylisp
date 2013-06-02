'''
Created on 2 jun. 2013

@author: sander
'''
import threading
from abc import ABCMeta, abstractmethod


class TaskThread(threading.Thread):
    """Thread that executes a task every N seconds"""

    __metaclass__ = ABCMeta

    def __init__(self, interval=15.0):
        threading.Thread.__init__(self)
        self._finished = threading.Event()
        self._interval = interval

    def set_interval(self, interval):
        """Set the number of seconds we sleep between executing our task"""
        self._interval = interval

    def shutdown(self):
        """Stop this thread"""
        self._finished.set()

    def run(self):
        while 1:
            if self._finished.isSet():
                return

            self.task()

            # sleep for interval or until shutdown
            self._finished.wait(self._interval)

    @abstractmethod
    def task(self):
        """The task done by this thread - override in subclasses"""
        pass
