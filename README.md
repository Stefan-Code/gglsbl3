gglsbl3
======

Python 3 client library for the Google Safe Browsing API (v3)

![Coverage](https://img.shields.io/badge/coverage-150%25-brightgreen.svg "Coverage") Just kidding. But hey, at least we have unit tests...
Disclaimer
----------
This Code is ported from here: https://github.com/afilipovich/gglsbl, although a lot of Unit Tests were added and a few more features introduced (like the ability to get the metadata for a match in a Safe Browsing List)
The master branch is experimental and unstable at the moment (until the first release). Use at your own risk!

While the code was developed according to official
[Developers Guide](https://developers.google.com/safe-browsing/developers_guide_v3)
this is **not** a reference implementation. You also may want to check
[Acceptable Use Policy](https://developers.google.com/safe-browsing/developers_guide_v3#AcceptableUsage)
for Safe Browsing API

Quick start
-----------

###### Get your Google API key
Instructions can be found [here](https://developers.google.com/safe-browsing/lookup_guide#GettingStarted)

###### Install the library

```
    python setup.py install
```

###### To sync the local hash cache

```python
    from gglsbl import SafeBrowsingList
    sbl = SafeBrowsingList('API KEY GOES HERE')
    sbl.update_hash_prefix_cache()
```

*On a first run it may take up to several hours to complete the sync, you may also have to run it several times*

###### URL lookup

```python
    from gglsbl import SafeBrowsingList
    sbl = SafeBrowsingList('API KEY GOES HERE')
    sbl.lookup_url('http://github.com/')
```
This will return a list of matched Safe Browsing lists, e.g.
```
[b'goog-malware-shavar']
```

CLI Tool
--------
*bin/gglsbl_client.py* can be used for quick testing and as a code example.

To sync local cache with Safe Browsing API omitting [Acceptable Use Policy](https://developers.google.com/safe-browsing/developers_guide_v3#AcceptableUsage) delays (which is not recommended!)
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
