import copy
from urllib.parse import urlparse, unquote
from concurrent.futures import ThreadPoolExecutor
from functools import partial

from core.colors import good, green, end
from core.requester import requester
from core.utils import getUrl, getParams
from core.log import setup_logger

logger = setup_logger(__name__)

def bruteforce_param(target, paramName, paramsCopy, payload, encoding, headers, GET, url, delay, timeout):
    progress = payload[0]
    payload = payload[1]
    logger.run('Bruteforcing %s[%s%s%s]%s: %i/%i\r' %
               (green, end, paramName, green, end, progress, len(payload)))
    if encoding:
        payload = encoding(unquote(payload))
    paramsCopy[paramName] = payload
    try:
        response = requester(url, paramsCopy, headers, GET, delay, timeout).text
    except Exception as e:
        logger.error('Error occurred during request: {}'.format(e))
        return
    if encoding:
        payload = encoding(payload)
    if payload in response:
        logger.info('%s %s' % (good, payload))

def bruteforcer(target, paramData, payloadList, encoding, headers, delay, timeout):
    GET, POST = (False, True) if paramData else (True, False)
    host = urlparse(target).netloc  
    logger.debug('Parsed host to bruteforce: {}'.format(host))
    url = getUrl(target, GET)
    logger.debug('Parsed url to bruteforce: {}'.format(url))
    params = getParams(target, paramData, GET)
    logger.debug_json('Bruteforcer params:', params)
    if not params:
        logger.error('No parameters to test.')
        return

    with ThreadPoolExecutor(max_workers=8) as executor:
        for paramName, paramValue in params.items():
            paramsCopy = copy.deepcopy(params)
            for payloadIndex, payload in enumerate(payloadList, start=1):
                executor.submit(bruteforce_param, target, paramName, copy.deepcopy(paramsCopy), (payloadIndex, payload), encoding, headers, GET, url, delay, timeout)
    logger.no_format('')
