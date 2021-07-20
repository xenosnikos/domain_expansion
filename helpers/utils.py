import socket
import os
import logging
import validators
from datetime import datetime, timedelta
import json
import requests
import queue
import threading

import pymongo
from helpers.mongo_connection import db
from helpers.requests_retry import retry_session
from helpers import common_strings

ip_location_dict = {}


def validate_domain(domain):
    if not validators.domain(domain):
        return False
    else:
        return True


def validate_domain_or_ip(value):
    if not (validators.domain(value) or validators.ipv4(value)):
        return False
    else:
        return True


def check_force(data, force, collection, timeframe, filter_by_ip=False):
    if force:
        return True

    if collection == common_strings.strings['expansion']:
        db[collection].create_index([(common_strings.strings['mongo_value'], pymongo.ASCENDING),
                                     (common_strings.strings['format_by_ip'], pymongo.ASCENDING)])
        search = db[collection].find_one({common_strings.strings['mongo_value']: data,
                                          common_strings.strings['format_by_ip']: filter_by_ip})
    else:
        db[collection].create_index(common_strings.strings['mongo_value'])
        search = db[collection].find_one({common_strings.strings['mongo_value']: data})

    if search is not None:
        if search['status'] == common_strings.strings['status_running'] or \
                search['status'] == common_strings.strings['status_queued']:
            return search['status']
        else:
            force = search['timeStamp'] + timedelta(days=timeframe) < datetime.utcnow()

    if force is False and search is not None:
        return search
    else:
        return True


def mark_db_request(value, status, collection, filter_by_ip=False):
    try:
        if collection == common_strings.strings['expansion']:
            db[collection].update_one({common_strings.strings['mongo_value']: value,
                                       common_strings.strings['format_by_ip']: filter_by_ip},
                                      {'$set': {'status': status}}, upsert=True)
        else:
            db[collection].update_one({common_strings.strings['mongo_value']: value}, {'$set': {'status': status}},
                                      upsert=True)
    except Exception as e:
        logger = logging.getLogger(collection)
        logger.critical(common_strings.strings['database_issue'], e)
    return True


def get_location_ip(ip):
    global ip_location_dict
    try:
        # Free API - has a limit of 15k requests per hour, it will start throwing a 403 after that limit at which we
        # want to handle the exception and go to the paid API
        resp = requests.get(f"{os.environ.get('FREE_GEOIP')}/{ip}")
        for each in json.loads(resp.text):
            # We don't worry about not fetching these fields from the free API
            if each == 'ip' or each == 'country_name' or each == 'region_code' or each == 'metro_code' or \
                    each == 'zip_code' or each == 'time_zone' or each == 'region_name':
                continue
            else:
                # In case we don't fetch the required field from free API, make a request to paid API
                if json.loads(resp.text)[each] == "":
                    raise Exception('All necessary fields not fetched')
    except Exception as e:
        logger = logging.getLogger(common_strings.strings['expansion'])
        logger.error(f'Exception occurred or value not fetched properly in freegeoip endpoint for {ip} - {e}')
        session = retry_session()
        try:
            # Paid API
            resp = session.get(f"{os.environ.get('WHOISXML_IP_LOCATION')}?apiKey={os.environ.get('API_KEY_WHOIS_XML')}"
                               f"&ipAddress={ip}")
        except Exception as e:
            logger.error(f'Exception occurred in whoisxml ip location endpoint {e}')
            resp = None
    # if location cannot be found in either of the calls, send an error back
    if resp is not None and resp.status_code == 200:
        if 'location' not in json.loads(resp.text):
            out = json.loads(resp.text)
            if 'metro_code' in out:
                del out['metro_code']
            if 'ip' in out:
                del out['ip']
            if 'country_name' in out:
                del out['country_name']
            if 'region_code' in out:
                del out['region_code']
            ip_location_dict[ip] = out
        else:
            out = json.loads(resp.text)['location']
            out['country_code'] = out.pop('country', common_strings.strings['error'])
            out['region_name'] = out.pop('region', common_strings.strings['error'])
            out['latitude'] = out.pop('lat', common_strings.strings['error'])
            out['longitude'] = out.pop('lng', common_strings.strings['error'])
            out['zip_code'] = out.pop('postalCode', common_strings.strings['error'])
            out['time_zone'] = out.pop('timezone', common_strings.strings['error'])
            del out['geonameId']
            ip_location_dict[ip] = out
    else:
        # Since location was not found in either of the calls, send an error back for all the fields
        out = {'country_code': common_strings.strings['error'], 'region_name': common_strings.strings['error'],
               'latitude': common_strings.strings['error'], 'longitude': common_strings.strings['error'],
               'zip_code': common_strings.strings['error'], 'time_zone': common_strings.strings['error'],
               'city': common_strings.strings['error']}
        ip_location_dict[ip] = out


def threader():
    while True:
        try:
            worker = q.get(timeout=0.1)
        except queue.Empty:
            break
        get_location_ip(worker)
        q.task_done()


def format_by_ip(sub_domains, out_format):
    out_dict = {}
    out_list = []
    out_blacklist = []
    blacklist_dict = {}
    out_sub_domain_count = 0

    blacklist = ['.nat.']

    for each_domain in sub_domains:
        try:
            ip = socket.gethostbyname(each_domain)  # we don't need to display sub-domains that do not have an IP
            for each_item in blacklist:
                if each_item in each_domain:
                    if each_item in blacklist_dict:
                        blacklist_dict[each_item] += 1
                    else:
                        blacklist_dict[each_item] = 1
                    break
            else:
                out_sub_domain_count += 1
                if out_format:
                    if ip in out_dict:
                        out_dict[ip] += [each_domain]
                    else:
                        out_dict[ip] = [each_domain]
                else:
                    out_list.append(each_domain)
        except:
            pass

    for each_ip in out_dict:
        q.put(each_ip)

    if len(out_dict) > 100:
        thread = 100
    else:
        thread = len(out_dict)

    for x in range(thread):
        t = threading.Thread(target=threader, daemon=False)
        t.start()

    q.join()

    if out_format:
        for each_item in out_dict:
            out_list.append({'ip': each_item, 'domains': out_dict[each_item],
                             common_strings.strings['location']: ip_location_dict[each_item]})

    ip_location_dict.clear()

    for each_blacklist in blacklist_dict:
        out_blacklist.append({'count': blacklist_dict[each_blacklist],
                              'reason': f"Blacklisted because the sub-domain contains '{each_blacklist}'"})

    return out_list, out_blacklist, out_sub_domain_count


def resolve_domain_ip(data_input):
    return socket.gethostbyname(data_input)


q = queue.Queue()
