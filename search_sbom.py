import argparse
import json

def search_sbom(sbom_file, component):

    print("Loading the SBOM...")
    sbom_dict = load_sbom(sbom_file)
    if (sbom_dict is None):
        return None

    print("Searching the SBOM...")
    count = search(sbom_dict, component)
    if (count is None):
        return None
    
    if count is None:
        count = 0
        
    return count


def load_sbom(sbom_file):

    # Load from file
    try:
        file1 = open(sbom_file, "r")
        sbom_str = file1.read()
        file1.close()   
    except FileNotFoundError as e:
        print("That file doesn't seem to exist. Please try again.")        
        return None
    except UnicodeDecodeError as e:
        print(e)
        print("File has some unexpected characters. Please make sure it's a CycloneDX-compliant SBOM and try again.")
        return None

    sbom_json = json.loads(sbom_str)

    return sbom_json
    

def search(sbom, component):

    # Verify that input is a CycloneDX SBOM in JSON format
    try:
        bom_format = sbom["bomFormat"]
    except KeyError as e:
        print("Error: 'bomFormat' element not found. A CycloneDX SBOM in JSON format is required.")        
        return None    

    if (bom_format != "CycloneDX"):
        print("Error: 'bomFormat' is not 'CycloneDX' as expected.")        
        return None

    # If SBOM has no components, write relevant message and return
    components = sbom["components"]
    if (components is None or len(components)==0):
        print("SBOM contains no components!")
        return 0
    
    num_found = 0    

    # Loop on all components in the SBOM
    for c in components:
        comp_type = c.get("type")

        # Get the library name and version.
        lib_name = c.get("name") if c.get("name") else " "
        lib_ver = c.get("version") if c.get("version") else " "
            
        # Look for match
        if (component in lib_name):
            print("Found match: " + lib_name + ", Component type: " + comp_type)
            num_found += 1

    return num_found

def main():

    parser = argparse.ArgumentParser(description="This script takes either a Veracode application or an SBOM file as input and generates a License Notice file for the open source software present.")
    parser.add_argument("-s", "--sbom_file", required=True, help="CycloneDX SBOM file to search.")
    parser.add_argument("-c", "--component", required=True, help="Component/library to search on.")

    args = parser.parse_args()
    sbom_file = args.sbom_file
    comp = args.component

    count = search_sbom(sbom_file.strip(), comp.strip())
    print("Done. Found " + str(count) + " instances.")


if __name__ == '__main__':
    main()
