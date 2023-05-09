import argparse
import json
import os

def search_for_component(file_list, component):

    total_count = 0
    for f in file_list:

        print("Searching: " + f)
        sbom_dict = load_sbom(f)
        if (sbom_dict is None):
            continue

        count = search_sbom(sbom_dict, component)
        if (count is None):
            continue
        
        total_count += count
       
    return total_count


def load_sbom(sbom_file):

    # Load from file
    try:
        file1 = open(sbom_file, "r")
        sbom_str = file1.read()
        file1.close()  
        sbom_json = json.loads(sbom_str) 
    except FileNotFoundError as e:
        print("That file doesn't seem to exist. Please try again.")        
        return None
    except UnicodeDecodeError as e:
        print("Can't read file. Unexpected characters found.")
        return None
    except json.decoder.JSONDecodeError as e:
        print("Can't read file. Invalid JSON data.")
        return None

    return sbom_json
    

def search_sbom(sbom, component):

    # Verify that input is a CycloneDX SBOM in JSON format
    try:
        bom_format = sbom["bomFormat"]
    except KeyError as e:
        print("Error: 'bomFormat' element missing - not a valid CycloneDX SBOM.")        
        return None    

    if (bom_format.lower() != "cyclonedx"):
        print("Error: 'bomFormat' is not 'CycloneDX' as required.")        
        return None

    # Increment the files count
    global files_count
    files_count += 1

    # If SBOM has no components, print relevant message and return
    components = sbom["components"]
    if (components is None or len(components)==0):
        print("SBOM contains no components!")
        return 0
    
    # Sort components by name (case insensitive)
    components.sort(key=lambda x:x['name'].lower()) 

    # Loop on all components in the SBOM
    num_found = 0
    for c in components:
        
        # Get the component type, name, and version.
        c_type = c.get("type") if c.get("type") else " "
        c_name = c.get("name") if c.get("name") else " "
        c_ver = c.get("version") if c.get("version") else " "
            
        # Look for match on the name, case insensitive
        if (component.lower() in c_name.lower()):
            print("Found match: " + c_name + ", Version: " + c_ver + ", Component type: " + c_type)
            num_found += 1

    return num_found


def main():

    parser = argparse.ArgumentParser(description="This script takes a component name and an SBOM as input and returns any matches that are found.")
    parser.add_argument("-s", "--sbom_file", required=True, help="CycloneDX SBOM file in JSON format. If set to 'ALL', every .json file in current directory will be searched.")
    parser.add_argument("-c", "--component", required=True, help="Component/library name you want to search for.")

    args = parser.parse_args()
    sbom_file = args.sbom_file
    comp = args.component

    global files_count
    files_count = 0

    file_list = []
    if (sbom_file == "ALL"):
        # Create list of all json files in current directory
        for x in os.listdir():
            if x.endswith(".json"):
                file_list.append(x)
    else:
        # Create list with the single file
        file_list.append(sbom_file)

    # Search the SBOM(s)
    tot_count = search_for_component(file_list, comp.strip())
    print("Done. Searched " + str(files_count) + " files and found " + str(tot_count) + " instances.")


if __name__ == '__main__':
    main()
