import sys
import argparse
import datetime

from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC

from veracode_api_py import VeracodeAPI as vapi
from veracode_api_py.sca import SBOM

def create_notice_file(app_name):

    print("Looking up application ID...")
    app_id = lookup_app_id(app_name)
    if (app_id is None):
        print ("Sorry, can't find that application in your Veracode account.")
        return None

    print("Retrieving SBOM...")
    sbom_dict = generate_sbom(app_id)
    if (sbom_dict is None):
        return None

    print("Building notice file...")
    filename = build_notice_file(sbom_dict)
    if (filename is None):
        return None

    return filename


def lookup_app_id(app_name):

    data = vapi().get_app_by_name(app_name)

    for app in data:
        profile = app.get("profile")
        if (profile.get("name") == app_name):
           app_id = app.get("guid")
           print("Application ID is: " + app_id)
           return app_id

    return None

       
def generate_sbom(app_id):

    try:
        sbom_dict = SBOM().get(app_id)
        return sbom_dict

    except Exception as e:
       print("Error trying to generate the SBOM. Do SCA results exist for this application? An SCA scan needs to have been done in the last 13 months.")
       return None
    

def build_notice_file(sbom):

    # Expected input to this function is a CycloneDX SBOM in JSON format

    # Grab the application name from the SBOM
    metadata = sbom["metadata"]
    app_name = metadata["component"].get("name") 
    if app_name is None or len(app_name)==0:
        app_name = "APPLICATION"

    # Truncate app name to 50 and remove chars that might cause filename issues
    app_name = app_name[:50]
    specials = "\"\\/:*?<>|"
    cleaned_name = "".join(c for c in app_name if c not in specials)
    filename = cleaned_name + "_notice.txt"

    with open(filename, 'w') as f:

        # Write header section
        print("==============================================================================", file=f)
        print("==                       OPEN SOURCE LICENSE NOTICE                         ==", file=f)
        print("==                                                                          ==", file=f)          
        print("==   This application uses open source software (OSS). The OSS components   ==", file=f)
        print("==   are used in accordance wtih the terms and conditions of the license    ==", file=f)
        print("==   under which the component is distributed. A list of components and     ==", file=f)
        print("==   their corresponding license(s) is provided below.                      ==", file=f)
        print("==                                                                          ==", file=f)            
        print("==============================================================================", file=f)
        print("", file=f)
        print("APPLICATION NAME: " + app_name, file=f)
        print("DATA SOURCE:      Veracode Software Composition Analysis (SCA) / SBOM API", file=f)
        print("GENERATED:        " + (datetime.datetime.now()).strftime("%c"), file=f)
        print("", file=f)

        # Set column widths
        wcol1 = 50
        wcol2 = 25
        wcol3 = 30
        wcol4 = 80

        # Write the column headers
        print("OSS COMPONENT NAME".ljust(wcol1) + "VERSION".ljust(wcol2) + "LICENSE".ljust(wcol3) + "LICENSE REFERENCE".ljust(wcol4), file=f)
        print("==================".ljust(wcol1) + "=======".ljust(wcol2) + "=======".ljust(wcol3) + "=================".ljust(wcol4), file=f)

        # If SBOM has no components, write relevant message and return
        components = sbom["components"]
        if (components is None or len(components)==0):
            print("No open source components", file=f)
            f.close()
            return filename

        # Loop on all components in the SBOM
        for c in components:
            comp_type = c.get("type")
            # Skip this component if not a library
            if (comp_type != "library"):
                continue
            # Get the library name and version. Truncate to column width minus 1 to keep things aligned.
            lib_name = c.get("name") if c.get("name") else " "
            lib_name = lib_name[:(wcol1-1)]
            lib_ver = c.get("version") if c.get("version") else " "
            lib_ver = lib_ver[:(wcol2-1)]
            # Write component info
            print(lib_name.ljust(wcol1) + lib_ver.ljust(wcol2), end="", file=f)
            # Skip ahead if licenses element is not present
            if "licenses" not in c.keys():
                print("", file=f)
                continue
            licenses = c["licenses"]
            # Skip ahead if licenses element is empty              
            if len(licenses) == 0:
                print("", file=f)
                continue
            # Write license info
            count = 0
            for l in licenses:
                count += 1
                # Note that license name in the SBOM may be under "id" or "name". Need to account for this.
                lic_id = l["license"].get("id")
                lic_name = l["license"].get("name")
                license_name = lic_id if lic_id is not None else lic_name
                license_name = license_name if license_name is not None else ""
                # Truncate to column width minus 1 to keep things aligned
                license_name = license_name[:(wcol3-1)]
                lic_url = l["license"].get("url")
                license_url = lic_url if lic_url is not None else ""
                # If 2 or more licenses for this component, first two columns need spaces to keep things aligned
                if count >= 2:
                    print(" ".ljust(wcol1) + " ".ljust(wcol2), end="", file=f)
                print(license_name.ljust(wcol3) + license_url.ljust(wcol4), file=f)

        f.close()

    return filename

def main():

    parser = argparse.ArgumentParser(description="This script takes application name as input and generates a Licenses Notice file for the open source software within that application.")
    parser.add_argument("--app_name", required=True, help="Application name within the Veracode platform.")

    args = parser.parse_args()

    app_name = args.app_name.strip()
    filename = create_notice_file(app_name)

    if filename is not None:
        print("Success! Created file \"" + filename + "\"")


if __name__ == '__main__':
    main()
