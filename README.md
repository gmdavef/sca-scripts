# sca-scripts
Python scripts that leverage the Veracode API to automate tasks or extend capabilities of Veracode Software Composition Analysis (SCA). These scripts are not officially supported by Veracode.

**Dependencies**

The following Python packages need to be installed:

* Veracode API Authentication library: [veracode-api-signing](https://pypi.org/project/veracode-api-signing/)
* Veracode API Helper library:  [veracode-api-py](https://pypi.org/project/veracode-api-py/)

**Authentication**

Option 1 - Save your Veracode API credentials in `~/.veracode/credentials` file as follows:

    [default]
    veracode_api_key_id = <YOUR_API_KEY_ID>
    veracode_api_key_secret = <YOUR_API_KEY_SECRET>

Option 2 - Save your Veracode API credentials in environment variables as follows:

    VERACODE_API_KEY_ID=<YOUR_API_KEY_ID>
    VERACODE_API_KEY_SECRET=<YOUR_API_KEY_SECRET>    

## generate_notice_file.py ##
Generates a simple License Notice file (sometimes called an Attribution Report) for an application that has been scanned by Veracode SCA. This helps to comply with open source licenses, which require a notice to describe the terms under which open source components have been made available. Currently works with SCA upload scans. Linked projects, if any, are included. Plain text is the only output file format at this time.

Alternatively, you can simply provide a CycloneDX SBOM file as input. Veracode API credentials are not required in that case.

**Usage**

`generate_notice_file.py [-h] <arguments>`

One of these arguments must be provided:
* `-a` or `--app_name` `<APPLICATION>` - name of the application within your Veracode account.
* `-s` or `--sbom_file` `<FILE>` - file name of a CycloneDX SBOM in JSON format.

NOTE: The generated file will be named "[NAME]_notice.txt" where [NAME] is the value of the metadata--\>component--\>name element in the SBOM.

**Examples**
```
> python generate_notice_file.py --app_name "Verademo application"
```
```
> python generate_notice_file.py --sbom_file "JuiceShop_sbom.json"
```