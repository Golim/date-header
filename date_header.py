#!/usr/bin/env python3

__author__ = "Matteo Golinelli"
__copyright__ = "Copyright (C) 2023 Matteo Golinelli"
__license__ = "MIT"

from crawler import Browser, Crawler
from cache_buster import CacheBuster
from cache_identification import CacheIdentification
from wcde import WCDE

from requests.exceptions import SSLError, ConnectionError, ReadTimeout, TooManyRedirects, ChunkedEncodingError, InvalidHeader
from urllib.parse import urlparse

import traceback
import argparse
import logging
import random
import json
import time
import sys
import os
import re

class bcolors:
    HEADER  = '\033[95m'
    OKBLUE  = '\033[94m'
    OKCYAN  = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL    = '\033[91m'
    ENDC    = '\033[0m'
    BOLD    = '\033[1m'
    UNDERLINE = '\033[4m'

TIMEOUT = 30

statistics = {}
network = {}


def save_dictionaries(site, crawler):
    """
    Save the dictionaries to files.
    """
    global statistics, network

    logs = {
        'queue':   crawler.queue,
        'visited': crawler.visited_urls
    }

    with open(f'logs/{site}-logs.json', 'w') as f:
        json.dump(logs, f, indent=4)
    with open(f'stats/{site}-stats.json', 'w') as f:
        json.dump(statistics, f, indent=4)
    with open(f'network/{site}-network.json', 'w') as f:
        json.dump(network, f, indent=4)

def get_dictionaries(site, crawler):
    """
    Load the dictionaries from the files.
    """
    global statistics, visited_urls, queue

    try:
        if os.path.exists(f'logs/{site}-logs.json'):
            with open(f'logs/{site}-logs.json', 'r') as f:
                logs = json.load(f)
                queue = logs['queue']
                visited_urls = logs['visited']

                crawler.set_visited_urls(visited_urls)
                crawler.set_queue(queue)
    except Exception as e:
        logging.error(f'ERROR: {e}')
    try:
        if os.path.exists(f'stats/{site}-stats.json'):
            with open(f'stats/{site}-stats.json', 'r') as f:
                statistics = json.load(f)
    except:
        pass


# =============================================================================
# =============================================================================
# =================================== MAIN ====================================
# =============================================================================
# =============================================================================

def main():
    global site, statistics, network

    logging.basicConfig()

    logger = logging.getLogger('cache_busting')

    logging.getLogger('urllib3').setLevel(logging.WARNING)

    parser = argparse.ArgumentParser(prog='cache_busting.py',
        description='Implementation of the detection methodology for ' + \
                    'Web Cache Deception vulnerabilities in a target website')

    parser.add_argument('-t', '--target',
        help='Target website')
    
    parser.add_argument('-u', '--url',
        help='URL to test')
    
    parser.add_argument('-r', '--retest', action='store_true',
        help='Retest the URLs that were already tested')

    parser.add_argument('-c', '--cookie',
        help='Cookies JSON file to use for the requests')

    parser.add_argument('-m', '--max', default=10,
        help=f'Maximum number of URLs to test for each domain/subdomain (default: {10})')

    parser.add_argument('-d', '--domains', default=2,
        help=f'Maximum number of domains/subdomains to test (default: {2})')
    
    parser.add_argument('-x', '--exclude', default='',
        help='Exclude URLs containing the specified regex(es) ' + \
            f'(use commas to separate multiple regexes).')

    parser.add_argument('-D', '--debug',    action='store_true',
        help='Enable debug mode')

    parser.add_argument('-R', '--reproducible', action='store_true',
        help='Use a seed for the random number generator to make the results reproducible')

    args = parser.parse_args()
    wcde = WCDE()

    if args.target:
        SITE = args.target.strip()
    elif args.url:
        SITE = urlparse(args.url).netloc.strip()

    if not args.target and not args.url:
        parser.print_help()
        sys.exit(0)

    if args.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    if args.cookie:
        cookies_file_name = args.cookie

        with open(cookies_file_name, 'r') as f:
            cookies = json.load(f)
    else:
        cookies = {}

    if not os.path.exists('logs'):
        os.mkdir('logs')
    if not os.path.exists('stats'):
        os.mkdir('stats')
    if not os.path.exists('network'):
        os.mkdir('network')

    if args.reproducible:
        random.seed(42)
    else:
        logger.info('Using true random numbers')

    site = SITE
    statistics['site'] = SITE
    statistics['cache_headers'] = False
    statistics['tested'] = False
    statistics['URLs'] = {}

    crawler = Crawler(site=SITE, max=int(args.max), max_domains=int(args.domains))

    USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"

    headers = {
        'User-Agent': USER_AGENT,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'DNT': '1',
        'Sec-GPC': '1'
    }

    logger.info(f'Started testing site: {SITE}')

    # Load the dictionaries from the files if they exist
    if not args.retest:
        get_dictionaries(SITE, crawler)

    if args.url:
        crawler.add_to_queue(args.url)
    else:
        for scheme in ['https', 'http']:
            crawler.add_to_queue(f'{scheme}://{SITE}/')
            crawler.add_to_queue(f'{scheme}://www.{SITE}/')

    if not crawler.should_continue():
        logger.info('Limit reached. Exiting.')
        sys.exit(0)

    if args.cookie:
        logger.info('Using provided cookies to create the victim\'s session.')

    browser = Browser(headers=headers, cookies=cookies)
    cache_buster = CacheBuster(site=SITE, headers=headers, cookies=cookies)
    cache_identification = CacheIdentification()

    while crawler.should_continue():
        try:
            url = crawler.get_url_from_queue()

            if url is None:
                break

            if crawler.is_visited(url):
                continue

            if args.exclude:
                if any(re.search(regex.strip(), url) for regex in args.exclude.split(',')):
                    continue

            parsed = urlparse(url)
            if any(parsed.path.endswith(ext) for ext in crawler.EXCLUDED_EXTENSIONS):
                continue

            logger.info(f'Visiting URL: {url}')

            # Request the URL
            try:
                response = browser.get(url, allow_redirects=True, timeout=TIMEOUT)
            except (SSLError, ConnectionError, ReadTimeout, TooManyRedirects, ChunkedEncodingError, InvalidHeader) as e:
                logger.error(f'ERROR: {url} -> {e}')
                if not 'errors' in statistics:
                    statistics['errors'] = []

                statistics['errors'].append({
                    'url': url,
                    'type': type(e).__name__,
                    'error': str(e),
                    'traceback': traceback.format_exc()
                })
                continue

            if not args.url:
                links = crawler.get_links(response.url, response.text)
                for link in links:
                    crawler.add_to_queue(link)

            crawler.add_to_visited(url)

            if response.url != url:
                url = response.url
                crawler.add_to_visited(url)

            # Save all the request and response headers
            network[url] = {
                'request1': {
                    'request': dict(response.request.headers),
                    'response': {
                        'status_code': response.status_code,
                        'headers': dict(response.headers)
                    }
                }
            }

            # Is the response coming from a cache or from the Origin? Is it cacheable?
            cache_status = wcde.cache_headers_heuristics(response.headers)
            if cache_status != '-':
                statistics['cache_headers'] = True

            # If it's a HIT: we have our request
            if cache_status == 'HIT':
                logger.info(f'The response gets cached -> cache_status = {cache_status}')

            # If it's a MISS: visit again and check if we get a HIT
            elif cache_status == 'MISS':
                # Request again two times to try and cache the response
                time.sleep(1)
                response2 = browser.get(url)
                time.sleep(2)
                response2 = browser.get(url)

                network[url]['request2'] = {
                    'request': dict(response2.request.headers),
                    'response': {
                        'status_code': response2.status_code,
                        'headers': dict(response2.headers)
                    }
                }

                cache_status2 = wcde.cache_headers_heuristics(response2.headers)
                if cache_status2 != '-':
                    statistics['cache_headers'] = True

                if cache_status2 == 'HIT':
                    logger.info(f'The response gets cached -> cache_status = {cache_status}/{cache_status2}')
                else:
                    logger.info(f'The response does not get cached -> cache_status = {cache_status}/{cache_status2}')
                    continue

            # If it's something else: continue to the next URL
            else:
                logger.info(f'The response does not get cached -> cache_status = {cache_status}')
                continue

            # If we are here, it means that the current URL gets cached
            logger.info(f'Testing the Date header on {url}')

            statistics['URLs'][url] = {
                'cache_status': cache_status if cache_status == 'HIT' else cache_status2,
                'date': [],
            }

            # Check if there is a Date header
            if 'response2' in network[url]:
                network[url]['first'] = {
                    'request': dict(response2.request.headers),
                    'response': {
                        'status_code': response2.status_code,
                        'headers': dict(response2.headers)
                    }
                }
                response_headers = response2.headers
            else:
                network[url]['first'] = {
                    'request': dict(response.request.headers),
                    'response': {
                        'status_code': response.status_code,
                        'headers': dict(response.headers)
                    }
                }
                response_headers = response.headers

            if 'Date' in response_headers:
                # Identify te cache
                cache = cache_identification.identify(response_headers)
                statistics['URLs'][url]['cache'] = cache
                logger.info(f'Identified cache: {bcolors.OKGREEN}{", ".join(cache)}{bcolors.ENDC}')

                logger.info(f'Found Date header: {response_headers["Date"]}')
                statistics['URLs'][url]['date'].append(response_headers['Date'])

                # Check if it's changing
                time.sleep(1.5)
                response2 = browser.get(url)
                network[url]['second'] = {
                    'request': dict(response2.request.headers),
                    'response': {
                        'status_code': response2.status_code,
                        'headers': dict(response2.headers)
                    }
                }

                if 'Date' in response2.headers:
                    logger.info(f'Found Date header: {response2.headers["Date"]}')
                    statistics['URLs'][url]['date'].append(response2.headers['Date'])

                    if response.headers['Date'] != response2.headers['Date']:
                        logger.info(f'The Date header is {bcolors.OKGREEN}changing{bcolors.ENDC}')
                    else:
                        logger.info(f'The Date header is {bcolors.WARNING}not changing{bcolors.ENDC}')

                    # Cache bust and check if it's changing
                    time.sleep(1.5)
                    _url, _headers, _cookies = cache_buster.cache_bust_request(
                        url,
                        headers=headers,
                        cookies=cookies,
                        vary=response_headers['Vary'] if 'Vary' in response_headers else '')

                    response3 = browser.get(_url, headers=_headers, cookies=_cookies, allow_redirects=False)
                    network[url]['third'] = {
                        'request': dict(response3.request.headers),
                        'response': {
                            'status_code': response3.status_code,
                            'headers': dict(response3.headers)
                        }
                    }

                    if 'Date' in response3.headers:
                        logger.info(f'Found Date header: {response3.headers["Date"]}')
                        statistics['URLs'][url]['date'].append(response3.headers['Date'])

                        if response_headers['Date'] != response3.headers['Date']:
                            logger.info(f'The Date header is {bcolors.OKGREEN}changing{bcolors.ENDC} after cache busting')
                        else:
                            logger.info(f'The Date header is {bcolors.WARNING}not changing{bcolors.ENDC} after cache busting')

            break # TODO: remove this to test more than one URL

        except KeyboardInterrupt:
            break
        except Exception as e:
            logger.error(f'ERROR: {url} -> {e}')
            logger.error(traceback.format_exc())
            if not 'errors' in statistics:
                statistics['errors'] = []
            statistics['errors'].append({
                'url': url,
                'type': type(e).__name__,
                'error': str(e),
                'traceback': traceback.format_exc()
            })


    # Save dictionaries to files
    save_dictionaries(SITE, crawler)

# =============================================================================
# =============================================================================
# =================================== MAIN ====================================
# =============================================================================
# =============================================================================

if __name__ == '__main__':
    main()
