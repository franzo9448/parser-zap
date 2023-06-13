import re
import netaddr
import glob

import yaml




class Config(object):
    def __init__(self):
        self.a = ""


    @staticmethod
    def colors():
        return {
            'blue': '#183868',
            'critical': '#702da0',
            'high': '#c80000',
            'medium': '#ffc000',
            'low': '#00b050',
            'informational': '#0070c0',
        }


    @staticmethod
    def levels():
        return {
            'c': 'critical',
            'h': 'high',
            'm': 'medium',
            'l': 'low',
            'i': 'informational'
        }


    @staticmethod
    def thresholds():
        return {
            'critical': 9.0,
            'high': 7.0,
            'medium': 4.0,
            'low': 0.1,
            'informational': 0.0
        }

    @staticmethod
    def cvss_color(cvss):
        for key in Config.thresholds():
            if cvss >= Config.thresholds()[key]:
                return Config.colors()[key]
        return None


    @staticmethod
    def cvss_level(cvss):
        for key in Config.thresholds():
            if cvss >= Config.thresholds()[key]:
                return key
        return None


    @staticmethod
    def min_levels():
        return {
            'critical': [Config.levels()['c']],
            'high': [Config.levels()['c'], Config.levels()['h']],
            'medium': [Config.levels()['c'], Config.levels()['h'], Config.levels()['m']],
            'low': [Config.levels()['c'], Config.levels()['h'], Config.levels()['m'], Config.levels()['l']],
            'informational': [Config.levels()['c'], Config.levels()['h'], Config.levels()['m'], Config.levels()['l'],
                     Config.levels()['i']]
        }