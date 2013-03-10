'''
Created on 3 feb. 2013

@author: sander
'''


def indent(text, spaces=4):
    prefix = ' ' * spaces
    return '\n'.join([prefix + line for line in text.split('\n')])


def represent(class_name, instance_dict, ignore=[]):
    params = ['%s=%r' % (key, value)
              for key, value in instance_dict.iteritems()
              if not key.startswith('_') and key not in ignore]

    return "%s(%s)" % (class_name, ', '.join(params))
