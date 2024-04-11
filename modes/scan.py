import re
import copy
import asyncio

from urllib.parse import urlparse, quote, unquote

from core.colors import end, green, que
from core.checker import checker
import core.config
from core.config import xsschecker, minEfficiency
from core.dom import dom
from core.filterChecker import filterChecker
from core.generator import generator
from core.htmlParser import htmlParser
from core.requester import requester
from core.utils import getUrl, getParams, getVar
from core.wafDetector import wafDetector
from core.log import setup_logger

logger = setup_logger(__name__)

def normalize_url(url, scheme, host):
    if url.startswith(scheme):
        return url
    elif url.startswith('//') and url[2:].startswith(host):
        return scheme + '://' + url[2:]
    elif url.startswith('/'):
        return scheme + '://' + host + url
    elif re.match(r'\w', url[0]):
        return scheme + '://' + host + '/' + url

async def analyze_payload(url, params, headers, is_get, delay, payload, positions, timeout, encoding, skip):
    vect = unquote(payload) if not is_get else payload
    if core.config.globalVariables['path']:
        vect = vect.replace('/', '%2F')
    logger_vector = payload
    efficiencies = checker(url, params, headers, is_get, delay, vect, positions, timeout, encoding)
    if not efficiencies:
        efficiencies = [0] * len(positions)
    best_efficiency = max(efficiencies)
    if best_efficiency >= minEfficiency:
        logger.red_line()
        logger.good('Payload: %s' % logger_vector)
        logger.info('Efficiency: %i' % best_efficiency)
        if not skip:
            choice = input('%s Would you like to continue scanning? [y/N] ' % que).lower()
            if choice != 'y':
                quit()

async def scan_payloads(url, params, headers, is_get, delay, vectors, positions, timeout, encoding, skip):
    total = sum(len(v) for v in vectors.values())
    if total == 0:
        logger.error('No vectors were crafted.')
        return
    logger.info('Payloads generated: %i' % total)
    progress = 0
    for confidence, vects in vectors.items():
        for vect in vects:
            progress += 1
            logger.run('Progress: %i/%i\r' % (progress, total))
            await analyze_payload(url, params, headers, is_get, delay, vect, positions, timeout, encoding, skip)
    logger.no_format('')

async def generate_payloads(url, form_data, headers, delay, timeout, encoding, skip):
    is_get = form_data['method'] == 'get'
    params = getParams(url, form_data['inputs'], is_get)
    logger.debug_json('Scan parameters:', params)
    if not params:
        logger.error('No parameters to test.')
        return
    params_copy = copy.deepcopy(params)
    params_copy[list(params.keys())[0]] = xsschecker
    WAF = wafDetector(url, params_copy, headers, is_get, delay, timeout)
    if WAF:
        logger.error('WAF detected: %s%s%s' % (green, WAF, end))
    else:
        logger.good('WAF Status: %sOffline%s' % (green, end))
    response = await requester(url, {}, headers, is_get, delay, timeout)
    occurences = htmlParser(response, encoding)
    positions = occurences.keys()
    logger.debug('Scan occurrences: {}'.format(occurences))
    if not occurences:
        logger.error('No reflection found')
        return
    else:
        logger.info('Reflections found: %i' % len(occurences))
    logger.run('Analysing reflections')
    efficiencies = filterChecker(url, params_copy, headers, is_get, delay, occurences, timeout, encoding)
    logger.debug('Scan efficiencies: {}'.format(efficiencies))
    vectors = generator(occurences, response.text)
    await scan_payloads(url, params_copy, headers, is_get, delay, vectors, positions, timeout, encoding, skip)

async def scan(scheme, host, main_url, form, blindXSS, blindPayload, headers, delay, timeout, encoding, skipDOM, skip):
    if form:
        tasks = []
        for form_url, form_data in form.items():
            url = normalize_url(form_data['action'], scheme, host)
            if url == main_url:
                continue
            tasks.append(generate_payloads(url, form_data, headers, delay, timeout, encoding, skip))
            if blindXSS and blindPayload:
                blind_params = {name: blindPayload for name in form_data['inputs']}
                tasks.append(requester(url, blind_params, headers, False, delay, timeout))
        await asyncio.gather(*tasks)
