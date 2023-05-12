import argparse
import json
import os

def search_for_component(file_list, component, csv_file):

    # Initialize overall match count to zero
    global overall_count
    overall_count = 0

    # Initialize an empty list for CSV rows
    csv_rows = []

    for f in file_list:

        print("Searching: " + f)
        sbom_dict = load_sbom(f)
        if (sbom_dict is None):
            # couldn't load this sbom, skip it
            continue

        count = search_sbom(f, sbom_dict, component, csv_rows)
        if (count is None):
            # this sbom has issues, skip it
            continue
        
        # Add to the overall match count
        overall_count += count

    # Output results to CSV if needed
    global csv_success
    csv_success = False    
    if ( overall_count>0 and csv_file is not None):
        csv_success = output_to_csv(csv_file, csv_rows)

    return overall_count


def load_sbom(sbom_file):

    # Read JSON data from file
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


def output_to_csv(csv_file, csv_rows):
   
    try:
        fcsv = open(csv_file, 'w')

        # Insert a header as first row
        hdr = "SBOM FILE, COMPONENT NAME, COMPONENT VERSION, COMPONENT TYPE"
        csv_rows.insert(0, hdr)
    
        for r in csv_rows:
            print(r, file=fcsv)

    except PermissionError as e:
        print("Error: Can't write to the output file! Is it in use?")
        return False

    fcsv.close()
    return True


def search_sbom(source_file, sbom, component, csv_rows):

    # Verify that input is a CycloneDX SBOM
    try:
        bom_format = sbom["bomFormat"]
    except KeyError as e:
        print("Error: 'bomFormat' element missing - not a valid CycloneDX SBOM.")        
        return None    

    if (bom_format.lower() != "cyclonedx"):
        print("Error: 'bomFormat' is not 'CycloneDX' as required.")        
        return None

    # We're good to continue, increment the files count
    global files_count
    files_count += 1

    # If SBOM has no components, print relevant message and return zero
    components = sbom["components"]
    if (components is None or len(components)==0):
        print("SBOM contains no components!")
        return 0

    # Sort components by name (case insensitive)
    components.sort(key=lambda x:x['name'].lower()) 

    global csv
    global overall_count
    num_found_in_sbom = 0 

    # Loop on all components in the SBOM
    for c in components:
        
        # Get the component type, name, and version.
        c_type = c.get("type") if c.get("type") else " "
        c_name = c.get("name") if c.get("name") else " "
        c_ver = c.get("version") if c.get("version") else " "
            
        # Look for match on the name, case insensitive
        if (component.lower() in c_name.lower()):
            # Found a match
            num_found_in_sbom += 1
            if (csv):
                csv_rows.append(source_file + "," + c_name + "," + c_ver + "," + c_type)
            else:
                print("Found match: " + c_name + ", Version: " + c_ver + ", Component type: " + c_type)

    return num_found_in_sbom


def main():

    parser = argparse.ArgumentParser(description="This script takes a component name and one or more SBOMs as input and returns any matches that are found.")
    parser.add_argument("-s", "--sbom_file", required=True, help="CycloneDX SBOM file in JSON format. If set to 'ALL', every .json file in current directory will be searched.")
    parser.add_argument("-c", "--component", required=True, help="Component/library name you want to search for.")
    parser.add_argument("-o", "--output_csv", required=False, help="Outputs results in CSV format to the specified file.")

    args = parser.parse_args()
    sbom_file = args.sbom_file
    comp = args.component
    csv_file = args.output_csv

    global csv
    csv = True if (csv_file is not None) else False

    global files_count
    files_count = 0

    file_list = []
    if (sbom_file == "ALL"):
        # Create a list of all json files in current directory
        for x in os.listdir():
            if x.endswith(".json"):
                file_list.append(x)
    else:
        # Create list with the single file
        file_list.append(sbom_file)

    # Search the SBOM(s)
    tot_count = search_for_component(file_list, comp.strip(), csv_file)
    print("Done. Searched " + str(files_count) + " files and found " + str(tot_count) + " instances.")

    global csv_success
    if (csv_success):
        print(("See " + csv_file) if tot_count > 0 else ("No output file created."))


if __name__ == '__main__':
    main()
