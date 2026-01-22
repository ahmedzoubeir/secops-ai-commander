import warnings
warnings.filterwarnings('ignore')

import os
os.environ['PYTHONWARNINGS'] = 'ignore'

# Now import and run demo1
from demo1 import demo

if __name__ == "__main__":
    demo()