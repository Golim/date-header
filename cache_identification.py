#!/usr/bin/env python3

__author__ = "Matteo Golinelli"
__copyright__ = "Copyright (C) 2023 Matteo Golinelli"
__license__ = "MIT"


class CacheIdentification:
    '''
    Identify the cache provider(s)
    based on the response headers
    '''

    KEYWORDS = {
        'akamai': {
            'name': [
                'x-akamai-',
                ],
            'value': [
                'akamai',
                'akamaitechnologies',
                'akamaiedge',
                'AkamaiGHost'
                ]
        },
        'cdn77': {
            'name': [
                'x-cdn77',
                'x-77'
                ],
            'value': [
                'cdn77',
                ]
        },
        'cloudflare': {
            'name': [
                'cf-cache-status',
                'cf-ray',
                'cf-request-id',

                ],
            'value': [
                'cloudflare'
                ]
        },
        'cloudfront': {
            'name': [
                'x-amz-cf-pop',
                'x-amz-cf-id',
                'x-amz-'
                ],
            'value': [
                'cloudfront',
                'cloudfront.net',
                ]
        },
        'fastly': {
            'name': [
                # 'x-served-by', # Might lead to false positives?
                ],
            'value': [
                'fastly',
                ]
        },
        'google': {
            'name': [
                'x-google-',
                'x-goog-',
                ],
            'value': [
                '1.1 google',
                ]
        },
        'keycdn': {
            'name': [
                # 'x-edge-location', false positives?
                ],
            'value': [
                'keycdn',
                ]
        },
        'azure': {
            'name': [
                'x-msedge-',
                ],
            'value': [
                'azure',
                ]
        },
        'apache, ats': {
            'name': [
                ],
            'value': [
                'apache',
                'ATS/',
                ]
        },
        'nginx': {
            'name': [
                'x-nginx'
                ],
            'value': [
                'nginx',
                ]
        },
        'rack_cache': {
            'name': [
                'x-rack-cache'
                ],
            'value': [
                'rack-cache',
                ]
        },
        'squid': {
            'name': [
                ],
            'value': [
                'squid',
                ]
        },
        'varnish': {
            'name': [
                'x-varnish',
                ],
            'value': [
                'varnish',
                ]
        },
    }

    DENYLIST = {
        'name': [
            'content-security-policy',
            'content-security-policy-report-only',
            'access-control-allow-origin',
        ],
        'value': [
        ]
    }

    def __init__(self):
        pass

    def identify(self, headers):
        providers = []

        for name, value in headers.items():
            if name in self.DENYLIST['name']:
                continue
            if value in self.DENYLIST['value']:
                continue

            for provider, keywords in self.KEYWORDS.items():
                if any(keyword.lower() in name.lower() for keyword in keywords['name']):
                    providers.append(provider)
                if any(keyword.lower() in value.lower() for keyword in keywords['value']):
                    providers.append(provider)

        return list(set(providers))
