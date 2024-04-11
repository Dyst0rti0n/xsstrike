import asyncio
import copy
import re

from core.colors import green, end
from core.config import xsschecker, globalVariables
from core.filterChecker import filterChecker
from core.generator import generator
from core.htmlParser import htmlParser
from core.requester import requester
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

async def crawl_form(url, form, headers, delay, timeout, encoding):
    method = form['method']
    GET = True if method == 'get' else False
    inputs = form['inputs']
    paramData = {one['name']: one['value'] for one in inputs}
    for paramName in paramData.keys():
        if paramName not in globalVariables['checkedForms'][url]:
            globalVariables['checkedForms'][url].append(paramName)
            paramsCopy = copy.deepcopy(paramData)
            paramsCopy[paramName] = xsschecker
            response = await requester(url, paramsCopy, headers, GET, delay, timeout)
            occurences = htmlParser(response, encoding)
            occurences = filterChecker(url, paramsCopy, headers, GET, delay, occurences, timeout, encoding)
            vectors = generator(occurences, response.text)
            if vectors:
                for confidence, vects in vectors.items():
                    try:
                        payload = next(iter(vects))
                        logger.vuln('Vulnerable webpage: %s%s%s' % (green, url, end))
                        logger.vuln('Vector for %s%s%s: %s' % (green, paramName, end, payload))
                        break
                    except IndexError:
                        pass

async def crawl(scheme, host, main_url, form, blindXSS, blindPayload, headers, delay, timeout, encoding):
    tasks = []
    if form:
        for form_url, form_data in form.items():
            url = normalize_url(form_data['action'], scheme, host)
            if url == main_url:
                continue
            globalVariables['checkedForms'].setdefault(url, [])
            tasks.append(crawl_form(url, form_data, headers, delay, timeout, encoding))
            if blindXSS and blindPayload:
                blind_params = {name: blindPayload for name in form_data['inputs']}
                tasks.append(requester(url, blind_params, headers, False, delay, timeout))
    await asyncio.gather(*tasks)
