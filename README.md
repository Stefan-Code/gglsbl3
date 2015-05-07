gglsbl3
======

Python 3 client library for the Google Safe Browsing API (v3)

![Coverage](https://img.shields.io/badge/coverage-150%25-brightgreen.svg "Coverage") Just kidding. But hey, at least we have unit tests...
###Disclaimer

The original code this project is based on can be found [here in afilipovich's repo](https://github.com/afilipovich/gglsbl). It was changed to support Python 3 (exclusively) and stuff like Unit Tests was added and a few more features introduced (like the ability to get the metadata for a match in the Google Safe Browsing List)
The master branch is experimental and unstable at the moment (until the first release). Use at your own risk! (as always)

While the code was developed according to official
[Developers Guide](https://developers.google.com/safe-browsing/developers_guide_v3)
this is **not** a reference implementation and is not connected with google in any way. You also may want to check
[Acceptable Use Policy](https://developers.google.com/safe-browsing/developers_guide_v3#AcceptableUsage)
for Safe Browsing API. Use this software at your on risk! (e.g. not complying with google standards)

Quick start
-----------

#### Get your Google API key
Instructions can be found [here](https://developers.google.com/safe-browsing/lookup_guide#GettingStarted)

#### Install the library
#####You can now install directly with pip! 

Just run:
```
pip install gglsbl3
```
And you should be all set!
#####Manual Installation
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
#####Important
*On a first run it may take up to several hours to complete the sync, you may also have to run it several times to fully sync the database. Before you can look up any urls, you have to sync the database.*

##### URL lookup

```python
    from gglsbl3 import SafeBrowsingList
    sbl = SafeBrowsingList('API KEY GOES HERE')
    sbl.lookup_url('http://github.com/')
```
This will return a list of matched Safe Browsing lists, e.g.
```
['goog-malware-shavar']
```

CLI Tool
--------
```scripts/gglsbl_client.py``` can be used for quick testing and as a code example.

To sync local cache with Safe Browsing API
```
    gglsbl_client.py --api-key 'API KEY GOES HERE'
```
The same, but omitting [Acceptable Use Policy](https://developers.google.com/safe-browsing/developers_guide_v3#AcceptableUsage) delays (which is not recommended!)
```
    gglsbl_client.py --api-key 'API KEY GOES HERE' --onetime
```

To look up URL
```
    gglsbl_client.py --api-key 'API KEY GOES HERE' --check-url http://github.com/
```

Fore more options please see
```
    gglsbl_client.py --help
```
If you have any more questions, feel free to open an issue or email me.
