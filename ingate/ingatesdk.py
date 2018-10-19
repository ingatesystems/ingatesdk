# -*- coding: utf-8 -*-
# MIT License

# Copyright (c) 2018 Ingate Systems AB

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import os
import ssl
import json
import socket
import base64
import time
try:
    import httplib
except ImportError:
    import http.client as httplib
try:
    from urllib.parse import urlencode as urlencode
except ImportError:
    from urllib import urlencode as urlencode


class SdkError(Exception):
    pass


class SdkValueError(SdkError):
    """Error class for value related errors.
    """
    pass


class SdkHttpError(SdkError):
    """Error class for HTTP related errors.
    """
    pass


class SdkJsonEncodeError(SdkError):
    """Error class for JSON encoding related errors.
    """
    pass


class SdkJsonDecodeError(SdkError):
    """Error class for JSON decoding related errors.
    """
    pass


class SdkAuthError(SdkError):
    """Error class for authentication related errors.
    """
    pass


class SdkFetchLicenseError(SdkError):
    """Error class for license related errors.
    """
    pass


class SdkFetchUpgradeError(SdkError):
    """Error class for upgrade related errors.
    """
    pass


class SdkCommandError(SdkError):
    """Error class for command related errors.
    """
    def __init__(self, message, code, errors):
        super(SdkCommandError, self).__init__(message)

        self.message = message
        self.code = code
        self.errors = errors

    def __str__(self):
        if self.errors:
            return '%d %s %s' % (self.code, self.message, self.errors)
        else:
            return '%d %s' % (self.code, self.message)


class Client(object):
    """This class implements the REST API client.
    """
    API_VERSIONS = ['v1']
    SCHEMES = ['http', 'https']
    WEBSYS_FETCH_ADDR = 'account.ingate.com'
    LICENSE_FETCH_PATH = '/api/get/license'
    UPGRADE_FETCH_PATH = '/api/get/upgrade'

    def __init__(self, version, scheme, address, user, password, port=''):
        """Initialize the client. Values passed here will later be used when
           communicating with the API.
        """
        self.__verify_https = True
        self.__token = None
        self.__auth_token = None

        if version not in self.API_VERSIONS:
            raise SdkValueError('%s is not a known API version' % (version))
        if scheme not in self.SCHEMES:
            raise SdkValueError('%s is not a known API scheme' % (scheme))

        self.__api_version = version
        self.__scheme = scheme
        self.__address = address
        self.__user = user
        self.__password = password
        self.__port = port
        self.__api_path = '/api/%s' % (self.__api_version)
        self.__api_address = self.__get_address_port()

    def __get_address_family(self, address):
        """Return the address family of 'address'. Returns socket.AF_INET if
           ipv4, socket.AF_INET6 for ipv6 and socket.AF_UNSPEC as default.
        """
        try:
            socket.inet_pton(socket.AF_INET, address)
            return socket.AF_INET
        except Exception:
            try:
                socket.inet_pton(socket.AF_INET6, address)
                return socket.AF_INET6
            except Exception:
                pass
        return socket.AF_UNSPEC

    def __get_address_port(self):
        """Return a address/port string. Prepares ipv6 addresses with hard
           brackets.
        """
        family = self.__get_address_family(self.__address)
        if family == socket.AF_INET6:
            address = '[' + self.__address + ']'
        else:
            address = self.__address
        if self.__port:
            address += ':' + self.__port
        return address

    def __fetch_license(self, username, password, liccode, cache_lic=True):
        """Download the license from the licensing system. This function
           assumes that the API client is authenticated.
        """
        unit_information = {}
        try:
            response = self.unit_information()
            info = response[0].get('unit-information')
            if info:
                unit_information['username'] = username
                unit_information['password'] = password
                unit_information['liccode'] = liccode
                unit_information['oemversion'] = info['version']
                unit_information['lang'] = info['lang']
                unit_information['machineid'] = info['systemid']
                unit_information['installid'] = info['installid']
                unit_information['macaddr'] = info['macaddr']
        except Exception as e:
            raise e

        params = urlencode(unit_information)
        headers = {'Content-type': 'application/x-www-form-urlencoded'}
        conn = httplib.HTTPSConnection(self.WEBSYS_FETCH_ADDR)
        try:
            conn.request('POST', self.LICENSE_FETCH_PATH, body=params,
                         headers=headers)
            resp = conn.getresponse()
            body = resp.read()
            status = resp.status
        except Exception as e:
            conn.close()
            raise SdkHttpError('Unable to fetch license. %s %s' %
                               (type(e).__name__, str(e)))

        if status != 200:
            conn.close()
            raise SdkFetchLicenseError(body)

        try:
            license_data = json.loads(body)
        except Exception as e:
            raise SdkJsonDecodeError('Failed to decode JSON string. %s' %
                                     (str(e)))

        license_b64 = license_data.get('license')
        if not license_b64:
            raise SdkFetchLicenseError('No license information found in'
                                       ' response.')
        if cache_lic:
            try:
                license_blob = base64.b64decode(license_b64)
            except Exception as e:
                raise SdkFetchLicenseError('Failed to base64 decode license'
                                           ' data. %s.' % str(e))
            date_time_str = time.strftime('%Y%m%d%H%M%S')
            fname_tmpl = 'license_%s_%s.lic'
            try:
                with open(fname_tmpl % (liccode, date_time_str), 'wb') as out:
                    out.write(license_blob)
            except Exception as e:
                raise SdkFetchLicenseError('Failed to write license to disk.'
                                           ' %s.' % str(e))
        conn.close()
        return license_b64

    def __fetch_upgrade_list(self, username, password):
        """Download version information from Ingate websystem. This function
           assumes that the API client is authenticated.
        """
        unit_information = {}
        try:
            response = self.unit_information()
            info = response[0].get('unit-information')
            if info:
                unit_information['username'] = username
                unit_information['password'] = password
                unit_information['oemversion'] = info['version']
                unit_information['machineid'] = info['systemid']
        except Exception as e:
            raise e

        params = urlencode(unit_information)
        headers = {'Content-type': 'application/x-www-form-urlencoded'}
        conn = httplib.HTTPSConnection(self.WEBSYS_FETCH_ADDR)
        try:
            conn.request('POST', self.UPGRADE_FETCH_PATH, body=params,
                         headers=headers)
            resp = conn.getresponse()
            body = resp.read()
            status = resp.status
        except Exception as e:
            conn.close()
            raise SdkHttpError('Unable to fetch upgrade list. %s %s' %
                               (type(e).__name__, str(e)))

        if status != 200:
            conn.close()
            raise SdkFetchUpgradeError(body)

        try:
            upgrade_data = json.loads(body)
        except Exception as e:
            raise SdkJsonDecodeError('Failed to decode JSON string. %s' %
                                     (str(e)))
        return upgrade_data

    def __fetch_upgrade(self, username, password, version):
        """Download upgrade from Ingate websystem. This function
           assumes that the API client is authenticated.
        """
        unit_information = {}
        try:
            response = self.unit_information()
            info = response[0].get('unit-information')
            if info:
                unit_information['username'] = username
                unit_information['password'] = password
                unit_information['wantedversion'] = version
                unit_information['oemversion'] = info['version']
                unit_information['machineid'] = info['systemid']
                unit_information['lang'] = info['lang']
        except Exception as e:
            raise e

        params = urlencode(unit_information)
        headers = {'Content-type': 'application/x-www-form-urlencoded'}
        conn = httplib.HTTPSConnection(self.WEBSYS_FETCH_ADDR)
        try:
            conn.request('POST', self.UPGRADE_FETCH_PATH, body=params,
                         headers=headers)
            resp = conn.getresponse()
            body = resp.read()
            status = resp.status
        except Exception as e:
            conn.close()
            raise SdkHttpError('Unable to fetch upgrade. %s %s' %
                               (type(e).__name__, str(e)))
        if status != 200:
            conn.close()
            raise SdkFetchUpgradeError(body)
        return body

    def __make_http_request(self, method, path, data=None, no_prefix=False,
                            send_token=True):
        """Makes the actual HTTP request. Returns the response body, status
           code, reason and headers.
        """
        if self.__scheme == 'http':
            conn = httplib.HTTPConnection(self.__api_address)
        else:
            ctx = None
            if not self.__verify_https:
                ctx = ssl._create_unverified_context()
            conn = httplib.HTTPSConnection(self.__api_address, context=ctx)

        headers = {}
        if not data:
            headers['Content-Length'] = '0'
        if data and method in ['POST', 'PUT']:
            headers['Content-Type'] = 'application/json'
        if send_token and self.__auth_token:
            headers['X-Auth-Token'] = self.__auth_token
        if no_prefix:
            url_path = path
        else:
            url_path = self.__api_path + '/' + path

        if data:
            try:
                json_body = json.dumps(data)
            except Exception as e:
                raise SdkJsonEncodeError('Failed to encode JSON string. %s' %
                                         (str(e)))
        else:
            json_body = None

        try:
            conn.request(method, url_path, body=json_body, headers=headers)
        except Exception as e:
            conn.close()
            raise SdkHttpError('Unable to send %s request to %s. %s %s' %
                               (self.__scheme, self.__api_address,
                                type(e).__name__, str(e)))
        try:
            resp = conn.getresponse()
            body = resp.read()
            status = resp.status
            reason = resp.reason
            headers = resp.getheaders()
        except Exception as e:
            conn.close()
            raise SdkHttpError('Unable to read response from %s. %s %s' %
                               (self.__api_address, type(e).__name__, str(e)))
        conn.close()
        return (status, reason, body, headers)

    def __get_http_header(self, name, headers, default=None):
        """Find a HTTP header by 'name' in 'headers'. If no header is found
           'default' is returned. Expects a list of (header, value) tuples.
        """
        name = name.lower()
        for header in headers:
            if header[0].lower() == name:
                return header[1]
        return default

    def __is_json_body(self, headers):
        """Return True if the headers indicate that there is a JSON body.
        """
        content_type = self.__get_http_header('content-type', headers)
        if not content_type:
            return False
        if content_type != 'application/json':
            return False
        return True

    def __get_json_body(self, body, headers):
        """Return a dictionary from the JSON body.
        """
        content_type = self.__get_http_header('content-type', headers)
        if not content_type:
            raise SdkHttpError('Failed to read content-type')
        if content_type != 'application/json':
            raise SdkHttpError('Body is not content-type application/json')
        try:
            json_body = json.loads(body)
        except Exception as e:
            raise SdkJsonDecodeError('Failed to decode JSON string. %s' %
                                     (str(e)))
        return json_body

    def __handle_response(self, response):
        """Handle the response from __make_http_request(). On success a
           dictionary is returned. On failure an Exception is thrown.
        """
        status, reason, body, headers = response
        if status == 200:
            if len(body) == 0:
                return {}
            return self.__get_json_body(body, headers)
        else:
            if len(body) > 0 and self.__is_json_body(headers):
                errors = self.__get_json_body(body, headers)
            else:
                errors = None
            raise SdkCommandError(reason, status, errors)

    def __run_command(self, method, command, data=None):
        """Call __make_http_request() and handle the response.
        """
        try:
            response = self.__make_http_request(method, command, data=data)
        except Exception as e:
            raise e
        return self.__handle_response(response)

    def wait_webserver(self, timeout=120, consecutive=15):
        """Wait for the unit to become available after e.g. a reboot or
           the installation of licenses. If you are experiencing issues
           with this function, increase the defaults for 'timeout' and
           'consecutive'.
        """
        retry = timeout * 2
        consecutive_ok = 0
        while retry > 0 and consecutive_ok < consecutive:
            try:
                status, _, _, _ = self.__make_http_request('GET', '/',
                                                           no_prefix=True)
                if status == 200:
                    consecutive_ok += 1
                else:
                    consecutive_ok = 0
            except Exception as e:
                consecutive_ok = 0
            time.sleep(0.5)
            retry -= 1

    def install_license(self, username, password, liccode, cache_lic=False,
                        license_b64=None):
        """Download and install a license from the Ingate licensing system.
           'username' and 'password' are the login credentials (the Account
           login on ingate.com). 'liccode' is the license code
           (e.g. KRJM-Q625-FUVG). 'cache_lic' toggels if the the license should
           be stored to disk when downloaded.

           If you already have downloaded a license file and want to install
           that license you can base64 encode that file and pass it as
           the parameter 'license_b64'. If you specify 'license_b64' the
           value of the other parameters doesn't matter.

           Note, after a license has been installed the API client needs to
           re-authenticate. The re-authentication is performed automatically
           by this function.
        """
        if license_b64:
            license_data = license_b64
        else:
            license_data = self.__fetch_license(username, password, liccode,
                                                cache_lic=cache_lic)
        data = {'data': {'license': license_data}}
        response = self.__run_command('POST', 'install-license', data=data)
        self.wait_webserver()
        self.authenticate()
        return response

    def download_install_upgrade(self, username, password, version=None,
                                 latest_patch=False, latest_minor=False,
                                 latest_major=False, latest=False):
        """Download and install an upgrade. 'username' and 'password' are the
           login credentials (the Account login on ingate.com).

           'version' is the desired version e.g. 6.2.1. 'latest_patch' will
           upgrade to the latest patch level. 'latest_minor' will upgrade
           to the latest minor level and 'latest_major' will upgrade to the
           latest major level. If the 'latest' argument is set to True, the unit
           will be upgraded to the latest available version.

           Note, after an upgrade has been installed the API client needs to
           re-authenticate. The re-authentication is performed automatically
           by this function. This method assumes that the the preliminary
           configuration has been stored to the permanent configuration at
           least once (see store_edit method).
        """
        def find_highest_patch(versions, major, minor, default=0):
            patch_level = default
            for version in versions:
                vmajor, vminor, vpatch = version.split('.')
                if int(major) == int(vmajor) and int(minor) == int(vminor):
                    if int(vpatch) > int(patch_level):
                        patch_level = vpatch
            return patch_level

        def find_highest_minor(versions, major, default=0):
            minor_level = default
            for version in versions:
                vmajor, vminor, vpatch = version.split('.')
                if int(major) == int(vmajor):
                    if int(vminor) > int(minor_level):
                        minor_level = vminor
            return minor_level

        def find_highest_major(versions, default=0):
            major_level = default
            for version in versions:
                vmajor, vminor, vpatch = version.split('.')
                if int(vmajor) > int(major_level):
                    major_level = vmajor
            return major_level

        def get_latest_patch(versions, major, minor, patch):
            patch_level = find_highest_patch(available_versions, major, minor,
                                             default=patch)
            return '%s.%s.%s' % (major, minor, patch_level)

        def get_latest_minor(versions, major, minor, patch):
            # Check if we have a next minor.
            minor_level = find_highest_minor(available_versions, major,
                                             default=minor)
            # We have a next minor. Get highest patch level.
            if int(minor_level) > int(current_minor):
                patch_level = find_highest_patch(available_versions,
                                                 major, minor_level)
            # No next minor, check for next patch level.
            else:
                return get_latest_patch(versions, major, minor, patch)
            return '%s.%s.%s' % (major, minor_level, patch_level)

        def get_latest_major(versions, major, minor, patch):
            # Check if we have a next major.
            major_level = find_highest_major(available_versions,
                                             default=current_major)
            # We have a next major. Get highest minor and patch level.
            if int(major_level) > int(current_major):
                minor_level = find_highest_minor(available_versions,
                                                 major_level)
                patch_level = find_highest_patch(available_versions,
                                                 major_level, minor_level)
            # No new major, check minor and patch level.
            else:
                return get_latest_minor(versions, major, minor, patch)
            return '%s.%s.%s' % (major_level, minor_level, patch_level)

        def is_next_minor(current_version, versions):
            cmajor, cminor, cpatch = current_version.split('.')
            for version in versions:
                vmajor, vminor, vpatch = version.split('.')
                if int(cmajor) == int(vmajor) and int(vminor) > int(cminor):
                    return True
            return False

        def is_next_major(current_version, versions):
            cmajor, cminor, cpatch = current_version.split('.')
            for version in versions:
                vmajor, vminor, vpatch = version.split('.')
                if int(vmajor) > int(cmajor):
                    return True
            return False

        # Latest is the latest available version.
        if latest:
            latest_major = True
            latest_minor = False
            latest_patch = False
            version = None

        # Check arguments.
        exclusive = [latest_major, latest_minor, latest_patch]
        if len([x for x in exclusive if x]) > 1:
            raise SdkValueError('latest_patch, latest_minor and'
                                ' latest_major are mutually exclusive.')
        if not version and len([x for x in exclusive if x]) == 0:
            raise SdkValueError('Need at least version and/or latest_major,'
                                ' latest_minor or latest_patch.')

        # Get unit-information.
        response = self.unit_information()
        unit_information = response[0].get('unit-information')
        current_version = unit_information['version'].split('-')[0]
        current_major, current_minor, current_patch = current_version.split('.')

        # Fetch a list of available versions.
        version_data = self.__fetch_upgrade_list(username, password)
        available_versions = version_data.get('versions')
        if available_versions is None:
            raise SdkFetchUpgradeError('Failed to retrieve available versions.')
        all_versions = version_data.get('all_versions')
        if all_versions is None:
            raise SdkFetchUpgradeError('Failed to retrieve all available'
                                       ' versions.')

        # Check that we have version(s) to upgrade to.
        if len(available_versions) == 0:
            return [{'download-install-upgrade':
                     {'msg':
                      'Your unit is upgraded to the latest version (%s)'
                      % current_version}}]

        # Check if we have reached the desired version.
        if version and version == current_version:
            return [{'download-install-upgrade':
                     {'msg':
                      'Your unit is upgraded to the desired version (%s)'
                      % current_version}}]

        # Check that the desired version exists.
        if version and version not in all_versions:
            raise SdkFetchUpgradeError('No such version exists (%s).' % version)

        wanted_version = None
        level_str = None
        if version and version in available_versions:
            level_str = 'desired'
            wanted_version = version
        elif latest_patch:
            level_str = 'patch'
            wanted_version = get_latest_patch(available_versions, current_major,
                                              current_minor, current_patch)
        elif latest_minor:
            level_str = 'minor'
            if not is_next_minor(current_version, all_versions):
                wanted_version = current_version
            else:
                wanted_version = get_latest_minor(available_versions,
                                                  current_major, current_minor,
                                                  current_patch)
        elif latest_major:
            level_str = 'major'
            if latest:
                level_str = 'available'
            if not latest and not is_next_major(current_version, all_versions):
                wanted_version = current_version
            else:
                wanted_version = get_latest_major(available_versions,
                                                  current_major, current_minor,
                                                  current_patch)
        if not wanted_version or not level_str:
            raise SdkFetchUpgradeError('No available version found.')

        if wanted_version == current_version:
            return [{'download-install-upgrade':
                     {'msg':
                      'Your unit is upgraded to the latest %s version (%s)'
                      % (level_str, current_version)}}]

        upgrade_blob = self.__fetch_upgrade(username, password, wanted_version)
        try:
            upgrade_data = base64.b64encode(upgrade_blob).decode('utf-8')
        except Exception as e:
            raise SdkJsonEncodeError('Failed to base64 encode the upgrade.')

        data = {'data': {'upgrade': upgrade_data}}
        self.__run_command('POST', 'install-upgrade', data=data)
        self.wait_webserver(timeout=300)
        self.authenticate()
        self.accept_upgrade()
        self.store_edit()
        return self.download_install_upgrade(username, password,
                                             version=version,
                                             latest_patch=latest_patch,
                                             latest_minor=latest_minor,
                                             latest_major=latest_major,
                                             latest=latest)

    def install_upgrade(self, filename):
        """Install an upgrade. The filename is a valid Ingate upgrade file.
           Note, after you have installed a license the unit will reboot
           and you need to re-authenticate and 'accept' or 'abort' the upgrade.

           Note, this method assumes that the the preliminary configuration has
           been stored to the permanent configuration at least once (see
           store_edit method).
        """
        with open(filename, 'rb') as inp:
            upgrade_blob = inp.read()
        upgrade_data = base64.b64encode(upgrade_blob).decode('utf-8')

        data = {'data': {'upgrade': upgrade_data}}
        response = self.__run_command('POST', 'install-upgrade', data=data)
        return response

    def accept_upgrade(self):
        """Accept an upgrade after an upgrade has been installed.
        """
        return self.__run_command('PUT', 'accept-upgrade')

    def abort_upgrade(self):
        """Abort an upgrade after an upgrade has been installed.
        """
        return self.__run_command('PUT', 'abort-upgrade')

    def downgrade_upgrade(self):
        """Downgrade from a previously installed upgrade.
        """
        return self.__run_command('PUT', 'downgrade-upgrade')

    def install_patch(self, filename):
        """Install a patch. The filename is a valid Ingate patch file.
           This method will wait for the unit to become available if
           the patch required a reboot. It will also re-authenticate
           the API client.

           Note, this method assumes that the the preliminary configuration has
           been stored to the permanent configuration at least once (see
           store_edit method).
        """
        with open(filename, 'rb') as inp:
            patch_blob = inp.read()
        patch_data = base64.b64encode(patch_blob).decode('utf-8')

        data = {'data': {'patch': patch_data}}
        response = self.__run_command('POST', 'install-patch', data=data)
        self.wait_webserver(timeout=300)
        self.authenticate()
        return response

    def skip_verify_certificate(self):
        """Don't verify the peer's HTTPS certificate.
        """
        self.__verify_https = False

    def verify_certificate(self):
        """Verify the peer's HTTPS certificate (the default).
        """
        self.__verify_https = True

    def authenticate(self):
        """Request a security token. At most one token per authenticated user.
           The token is bound to the IP address from which the user acquired
           the token.
        """
        auth_data = {'auth': {'user': self.__user,
                              'password': self.__password}}
        try:
            response = self.__make_http_request('POST', 'auth-token',
                                                data=auth_data,
                                                send_token=False)
        except Exception as e:
            raise e

        status, reason, body, headers = response
        if status == 200:
            res = self.__get_json_body(body, headers)
            self.__token = res
            token_str = self.__get_http_header('x-subject-token', headers)
            if not token_str:
                raise SdkAuthError('Failed to read authentication token'
                                   ' from response')
            self.__auth_token = token_str
            return res
        else:
            raise SdkAuthError('Failed to authenticate (%s)' % (reason))

    def unit_information(self):
        """Get information about the unit.
        """
        return self.__run_command('GET', 'unit-information')

    def revert_edits(self):
        """Reset the preliminary configuration to the permanent configuration.
        """
        return self.__run_command('PUT', 'revert-edits')

    def list_errors(self):
        """List all errors in all tables in the preliminary configuration.
        """
        return self.__run_command('GET', 'list-errors')

    def list_tables(self):
        """List all tables.
        """
        return self.__run_command('GET', 'list-tables')

    def describe_tables(self):
        """Describe all tables, listing its columns and their types.
        """
        return self.__run_command('GET', 'describe-tables')

    def load_factory(self):
        """Reset the preliminary configuration to their factory defaults.
        """
        return self.__run_command('PUT', 'load-factory')

    def list_timezones(self):
        """List all available timezones.
        """
        return self.__run_command('GET', 'list-timezones')

    def get_datetime(self):
        """Get the current date, time and timezone.
        """
        return self.__run_command('GET', 'datetime')

    def set_datetime(self, **kwargs):
        """Set the current date, time and timezone.
        """
        zone = kwargs.get('zone')
        date = kwargs.get('date')
        time = kwargs.get('time')
        datetime = {'data': {}}
        if zone:
            datetime['data']['zone'] = zone
        if date:
            datetime['data']['date'] = date
        if time:
            datetime['data']['time'] = time
        return self.__run_command('PUT', 'datetime', data=datetime)

    def operational_mode(self, mode):
        """Set mode to siparator or firewall. Requires a reboot to be applied.
        """
        opmode = {'data': {'mode': mode}}
        return self.__run_command('PUT', 'operational-mode', data=opmode)

    def reboot(self):
        """Reboot the unit. A new security token must be acquired after a
           reboot.
        """
        response = self.__run_command('PUT', 'reboot')
        self.wait_webserver(timeout=300)
        self.authenticate()
        return response

    def store_edit(self):
        """Store the preliminary configuration to the permanent configuration.
        """
        return self.__run_command('PUT', 'store-edit')

    def download_config(self, store=False, path=None, filename=None):
        """Download configuration database from the unit.
           - store - If the configuration should be stored on disk.
           - path - Where in the filesystem to store the configuration.
           - filename - The name of the file to store.
           If store is set to True, and path and filename is omitted,
           the file will be stored in the current directory with an
           automatic filename.
        """
        response = self.__run_command('GET', 'download-config')
        if store:
            if filename is not None:
                fname = filename
            else:
                fname = response[0]['download-config']['filename']
            if path is not None:
                fpath = path
            else:
                fpath = ''
            with open(os.path.join(fpath, fname), 'w') as outp:
                outp.write(response[0]['download-config']['config'])
        return response

    def add_row(self, table, **kwargs):
        """Add a row to a table.
        """
        row_data = {'data': {}}

        for column, value in kwargs.items():
            row_data['data'][column] = value
        table_path = table.replace('.', '/')
        return self.__run_command('POST', table_path, data=row_data)

    def delete_row(self, table, rowid):
        """Delete a specific row in a table.
        """
        table_path = table.replace('.', '/')
        table_path += '/%s' % (rowid)
        return self.__run_command('DELETE', table_path)

    def delete_table(self, table):
        """Delete all rows in a table.
        """
        table_path = table.replace('.', '/')
        return self.__run_command('DELETE', table_path)

    def modify_single_row(self, table, **kwargs):
        """Modify a single row table row.
        """
        row_data = {'data': {}}

        for column, value in kwargs.items():
            row_data['data'][column] = value
        table_path = table.replace('.', '/')
        return self.__run_command('PUT', table_path, data=row_data)

    def modify_row(self, table, rowid, **kwargs):
        """Modify a specific table row.
        """
        row_data = {'data': {}}

        for column, value in kwargs.items():
            row_data['data'][column] = value
        table_path = table.replace('.', '/')
        table_path += '/%s' % (rowid)
        return self.__run_command('PUT', table_path, data=row_data)

    def dump_table(self, table):
        """Get the contents of all rows in a table.
        """
        table_path = table.replace('.', '/')
        return self.__run_command('GET', table_path)

    def dump_row(self, table, rowid):
        """Get the contents of a specific row in a table.
        """
        table_path = table.replace('.', '/')
        table_path += '/%s' % (rowid)
        return self.__run_command('GET', table_path)
