gglsbl3
======

Python 3 client library for the Google Safe Browsing API (v3)

[![Build Status](https://travis-ci.org/Stefan-Code/gglsbl3.svg)](https://travis-ci.org/Stefan-Code/gglsbl3)
[![Build status](https://ci.appveyor.com/api/projects/status/m0x4rrd27mxfarf4/branch/master?svg=true)](https://ci.appveyor.com/project/Stefan-Code/gglsbl3/branch/master)
[![Coverage Status](https://coveralls.io/repos/Stefan-Code/gglsbl3/badge.svg?branch=master&service=github)](https://coveralls.io/github/Stefan-Code/gglsbl3?branch=master)
[![License](https://img.shields.io/pypi/l/gglsbl3.svg)](https://github.com/Stefan-Code/gglsbl3/blob/master/LICENSE)
![Python Version](https://img.shields.io/pypi/pyversions/gglsbl3.svg)

The original code this project is based on can be found [here in afilipovich's repo](https://github.com/afilipovich/gglsbl). It was changed to support Python 3 (exclusively) and stuff like Unit Tests was added and a few more features introduced (like the ability to get the metadata for a match in the Google Safe Browsing List)
The master branch is used for development, use a release if you want stability.

While the code was developed according to official
[Developers Guide](https://developers.google.com/safe-browsing/developers_guide_v3)
this is **not** a reference implementation and is not affiliated with google in any way. You also may want to check
 the [Acceptable Use Policy](https://developers.google.com/safe-browsing/developers_guide_v3#AcceptableUsage)
for Safe Browsing API. Use this software at your own risk!

Important information
---------------
This is **not** an implementation for the [Google Safe Browsing Lookup API](https://developers.google.com/safe-browsing/lookup_guide?hl=en).
The lookup API would be using HTTP requests for *each* lookup you perform. The implementation used here instead, downloads an *offline copy* of a part of the database,
which allows you to exceed the rate limit of the lookup API. Because of that you have to synchronise the database on the first run though.

Quick start
-----------

#### Get your Google API key
Instructions can be found [here](https://developers.google.com/safe-browsing/lookup_guide#GettingStarted)

#### Install the library
##### Using `pip` (recommended)

Just run:
~~~
pip install gglsbl3
~~~
And you should be all set!
##### Manual Installation

Download the library, locate setup.py and run
```
python setup.py install
```

##### To sync the local hash cache

```python
from gglsbl3 import SafeBrowsingList
sbl = SafeBrowsingList('GOOGLE SAFE BROWSING V3 API KEY HERE')
sbl.update_hash_prefix_cache()
```
##### Important
On a first run it may take up to **several hours** to complete the sync, you may also have to run it several times to fully sync the database. Before you can look up any urls, you have to sync the database.

##### URL lookup

```python
from gglsbl3 import SafeBrowsingList
sbl = SafeBrowsingList('API KEY GOES HERE')
lookup_result = sbl.lookup_url('http://github.com/')
```
This will return a list of matched Safe Browsing lists, e.g.
```
>>> print(lookup_result)
['goog-malware-shavar']
```

CLI Tool
--------
`scripts/gglsbl_client.py` can be used for quick testing and as a code example. When installing with `pip` or `setup.py install` this tools should automatically be in your `PATH`.

To sync local cache with Safe Browsing API
```
    gglsbl_client.py --api-key 'API KEY GOES HERE'
```
The same, but omitting [Acceptable Use Policy](https://developers.google.com/safe-browsing/developers_guide_v3#AcceptableUsage) delays (which is not recommended!)
```
    gglsbl_client.py --api-key 'API KEY GOES HERE' --onetime
```

To look up a URL
```
    gglsbl_client.py --api-key 'API KEY GOES HERE' --check-url http://github.com/
```

Fore more options please see
```
    gglsbl_client.py --help
```
If you have any more questions, feel free to open an issue or email me.
