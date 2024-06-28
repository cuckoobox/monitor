monitor
=======

The new Cuckoo Monitor. [Click here for documentation][docs].
If at first it doesn't compile, just try a second time!

**New Features:**
- Now supports running in Windows 10 and Windows 11 guest environments.

**Notes:**
- The issue with x86-64 samples where hooks could not jump back to the original function execution flow has been resolved. There may still be other issues, which are currently under development and testing.

- Note that you'll need the `pyyaml` package, which may be installed as follows:
 `pip install pyyaml`.

[docs]: http://cuckoo-monitor.readthedocs.org/en/latest/
