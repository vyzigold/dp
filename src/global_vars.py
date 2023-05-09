"""Module for holding global variables.

These variables are used across the whole project.
It might be possible to get rid of them and implement
special functions or parameters across the whole project,
but that would add some necessary complexity.

@author Jaromir Wysoglad (xwysog00)
"""


class Globals:
    # When this variable is set to True, all running
    # threads will end their execution as fast as possible
    # gets set to True by the signal handling function in the
    # main.py file
    DONE = False

    # When this variable is set to True, the script starts
    # to output a lot more debug outputs. It's set to True
    # by the configuration parsing part of the project
    DEBUG = False
