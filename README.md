# Ingate Python SDK

## Overview
The Ingate Python SDK provides an interface to configure and manage your Ingate
appliances (including upgrades, licenses and patches) via HTTP requests.

## Examples

### Change the unit name
Change the name of the unit to *Testapi*. Create a *Client* instance. Request a
security token. Call the method *modify_single_row* in order to change the name
and print the result. Store the change to the permanent configuration.

~~~~
import sys

from ingate import ingatesdk

scheme = 'http'
user = 'alice'
password = 'foobar'
address = '192.168.1.1'
port = ''

try:
    # Create API client.
    api_client = ingatesdk.Client('v1', scheme, address, user, password,
                                  port=port)

    # Authenticate and get hold of a security token.
    response = api_client.authenticate()

    # Change the unit name.
    unitname = 'Testapi'
    response = api_client.modify_single_row('misc.unitname', unitname=unitname)
    print('Changed the unit name to %s' % (response[0]['data']['unitname']))
    print('')

    # Store the preliminary configuration to the permanent configuration.
    response = api_client.store_edit()
    print(response[0]['store-edit']['msg'])
    print('')

except Exception as e:
    sys.stderr.write('\n%s: %s\n' % (type(e).__name__, str(e)))
~~~~

### Apply a base license and upgrade to latest firmware version
~~~~
import sys

from ingate import ingatesdk

scheme = 'http'
user = 'alice'
password = 'foobar'
address = '192.168.1.1'
port = ''

try:
    # Create API client.
    api_client = ingatesdk.Client('v1', scheme, address, user, password,
                                  port=port)

    # Authenticate and get hold of a security token.
    response = api_client.authenticate()

    # Install a license.
    response = api_client.install_license('myaccount', 'mypassword',
                                          'JJV8-9JVT-BV36')

    # Store the edit configuration. The 'download_install_upgrade' function
    # expects that the configuration has been stored at least once.
    api_client.store_edit()

    # Upgrade to the latest version available.
    response = api_client.download_install_upgrade('myaccount', 'mypassword',
                                                   latest=True)

except Exception as e:
    sys.stderr.write('\n%s: %s\n' % (type(e).__name__, str(e)))
~~~~

## Additional information
* [More information and examples](https://account.ingate.com/manuals/latest/reference_guide.html#_python_sdk)
