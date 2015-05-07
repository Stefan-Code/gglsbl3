gglsbl3
=======
Python 3 client library for the Google Safe Browsing API (v3) 
The source code for this library can be found `here on github.com <https://github.com/Stefan-Code/gglsbl3>`__

Please note that this Program *only* supports **Python 3**.

While the code was developed according to official `Developers
Guide <https://developers.google.com/safe-browsing/developers_guide_v3>`__, 
this is **not** a reference implementation and is not connected with
google in any way. You also may want to check `Acceptable Use
Policy <https://developers.google.com/safe-browsing/developers_guide_v3#AcceptableUsage>`__
for Safe Browsing API.

Quick start
-----------

First, get your Google API from
`here <https://developers.google.com/safe-browsing/lookup_guide#GettingStarted>`__
and then download then download this library (when not installing with pip)

Installing
~~~~~~~~~~
::

        python setup.py install

Alternatively, you can also install this library with pip by running:

::

        pip install gglsbl3


Syncing the local hash cache
~~~~~~~~~~~~~~~~~~~~~~~~~~~~                            

::

        from gglsbl3 import SafeBrowsingList
        sbl = SafeBrowsingList('GOOGLE SAFE BROWSING V3 API KEY HERE')
        sbl.update_hash_prefix_cache()

Please note that a first run it may take up to several hours to complete the sync,
you may also have to run it several times to fully sync the database

URL lookup
~~~~~~~~~~          

::

        from gglsbl3 import SafeBrowsingList
        sbl = SafeBrowsingList('API KEY GOES HERE')
        sbl.lookup_url('http://github.com/')


This will return a list of matched Safe Browsing lists, e.g.

::

    ['goog-malware-shavar']


CLI Tool
~~~~~~~~

*scripts/gglsbl_client.py* can be used for quick testing and as a code example.
To sync local cache with Safe Browsing API omitting `Acceptable Use Policy <https://developers.google.com/safe-browsing/developers_guide_v3#AcceptableUsage>`__
delays (which is not recommended!)

::

       gglsbl_client.py --api-key 'API KEY GOES HERE' --onetime

**To look up an URL**

::

       gglsbl_client.py --api-key 'API KEY GOES HERE' --check-url http://github.com/

Fore more options please see

::

       gglsbl_client.py --help
