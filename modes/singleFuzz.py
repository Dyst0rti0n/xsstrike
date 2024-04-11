import copy
from urllib.parse import urlparse

import requests  # Import requests library for handling HTTP requests

from core.colors import green, end
from core.config import xsschecker
from core.fuzzer import fuzzer
from core.requester import requester
from core.utils import getUrl, getParams
from core.wafDetector import wafDetector
from core.log import setup_logger

logger = setup_logger(__name__)

def singleFuzz(target, paramData, encoding, headers, delay, timeout):
    GET, POST = (False, True) if paramData else (True, False)
    
    # Handle URL prefix (http/https)
    if not target.startswith('http'):
        try:
            response = requester('https://' + target, {}, headers, GET, delay, timeout)
            target = 'https://' + target
        except requests.exceptions.RequestException as e:
            logger.error('Error occurred while making HTTPS request: {}'.format(e))
            target = 'http://' + target
    
    logger.debug('Target URL: {}'.format(target))
    host = urlparse(target).netloc
    logger.debug('Host: {}'.format(host))
    url = getUrl(target, GET)
    logger.debug('Final URL: {}'.format(url))
    params = getParams(target, paramData, GET)
    logger.debug_json('Parameters:', params)
    
    if not params:
        logger.error('No parameters found for fuzzing.')
        return

    # WAF detection
    try:
        waf_status = wafDetector(url, {list(params.keys())[0]: xsschecker}, headers, GET, delay, timeout)
        if waf_status:
            logger.error('WAF detected: {}{}'.format(green, waf_status, end))
        else:
            logger.good('WAF Status: {}Offline{}'.format(green, end))
    except Exception as e:
        logger.error('Error occurred during WAF detection: {}'.format(e))
        # Log the specific error encountered during WAF detection
        logger.debug('WAF detection error details:', exc_info=True)

    for param_name in params.keys():
        logger.info('Fuzzing parameter: {}'.format(param_name))
        params_copy = copy.deepcopy(params)
        params_copy[param_name] = xsschecker
        fuzzer(url, params_copy, headers, GET, delay, timeout, waf_status, encoding)
