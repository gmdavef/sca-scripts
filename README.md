# sca-scripts
Various Python scripts to automate tasks or extend capabilities of Software Composition Analysis (SCA) tools or to work with Software Bills of Material (SBOMs).

## search_sbom.py ##
This script searches the given SBOM(s) for the presence of a specific component. Only SBOMs in CycloneDX JSON format are supported. The search is case insensitive.

**Usage**

`search_sbom.py [-h] <arguments>`

Both of these arguments must be provided:
* `-s` or `--sbom_file` `<FILE>` - file name of a CycloneDX SBOM in JSON format. If set to 'ALL', every .json file in current directory will be searched.
* `-c` or `--component` `<COMPONENT>` - name of the component/library you want to search for.

**Examples**
```
> python search_sbom.py --sbom_file MyJavaApp_sbom.json --component log4j
```
```
> python search_sbom.py --sbom_file ALL --component ua-parser-js
```
## generate_notice_file.py ##
This script generates a simple License Notice file (sometimes called an Attribution Report) to help to comply with open source licenses, which require a notice to describe the terms under which open source components have been made available in a piece of software. Plain text is the only output file format at this time.

This script takes a CycloneDX SBOM as input. Note that if the SBOM doesn't include license data for the open source components, the License Notice file won't have it either.

Alternatively, the script can be used by Veracode SCA customers by specifying an application that has been scanned via the Upload Scan method. Linked projects, if any, are included. Veracode API credentials and other dependencies are required as noted below. This script is not officially supported by Veracode.

**Usage**

`generate_notice_file.py [-h] <arguments>`

One of these arguments must be provided:
* `-s` or `--sbom_file` `<FILE>` - file name of a CycloneDX SBOM in JSON format.
* `-a` or `--app_name` `<APPLICATION>` - name of the application within your Veracode account.

The generated file will be named "[NAME]_notice.txt" where [NAME] is taken from the metadata--\>component--\>name element in the SBOM.

**Examples**
```
> python generate_notice_file.py --sbom_file "JuiceShop_sbom.json"
```
```
> python generate_notice_file.py --app_name "Verademo application"
```

**Requirements if using Veracode**

The following Python packages need to be installed:

* Veracode API Authentication library: [veracode-api-signing](https://pypi.org/project/veracode-api-signing/)
* Veracode API Helper library:  [veracode-api-py](https://pypi.org/project/veracode-api-py/)

To authenticate with the Veracode API:

Option 1 - Save your Veracode API credentials in `~/.veracode/credentials` file as follows:

    [default]
    veracode_api_key_id = <YOUR_API_KEY_ID>
    veracode_api_key_secret = <YOUR_API_KEY_SECRET>

Option 2 - Save your Veracode API credentials in environment variables as follows:

    VERACODE_API_KEY_ID=<YOUR_API_KEY_ID>
    VERACODE_API_KEY_SECRET=<YOUR_API_KEY_SECRET>

