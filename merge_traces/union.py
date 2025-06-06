import argparse

if __name__ == '__main__':
    """
    Merge multiple CSV files into a single one.
    The timestamps of the traces are aligned to the first timestamp of the reference file.

    Comand line arguments:
    --csv-files: List of CSV file names to merge
    --output: Output CSV file name
    --file-reference: Reference CSV file name to align the timestamps

    Example:
    python merge_traces/union.py --csv-files trace1.csv trace2.csv trace3.csv --output merged.csv --file-reference trace1.csv
    """
    args = argparse.ArgumentParser()
    args.add_argument("--csv-files", nargs='+', help="List of CSV file names to merge", required=True)
    args.add_argument("--output", "-o", type=str, help="Output CSV file name", required=True)
    args.add_argument("--file-reference", "-r", type=str, help="Reference CSV file name to align the timestamps", required=True)
    args = args.parse_args()

    print('Union of traces')
    print('----------------')

    print('Reading traces...')

    files = args.csv_files
    output = args.output
    file_reference = args.file_reference

    assert file_reference in files, "Reference file not found in the list of files"
    assert len(files) > 1, "At least two files are needed to merge"

    with open(file_reference, 'r') as f:
        lines = f.readlines()
        first_timestamp = float(lines[1].split(',')[2])

    out_file = open(output, 'w')
    # Write the header
    with open(files[0], 'r') as f:
        out_file.write(f.readline())
    for f in files:
        relative_first_timestamp = None
        with open(f, 'r') as f:
            if f == file_reference:
                # Copy the content of the reference file, but excluding the header
                lines = f.readlines()
                for l in lines[1:]:
                    out_file.write(l)
            else:
                lines = f.readlines()
                for l in lines[1:]:
                    if relative_first_timestamp is None:
                        relative_first_timestamp = float(l.split(',')[2])
                    timestamp = float(l.split(',')[2])
                    new_timestamp = first_timestamp + (timestamp - relative_first_timestamp)
                    l_split = l.split(',')
                    l_split[2] = str(new_timestamp)
                    out_file.write(','.join(l_split))
    out_file.close()

    # Order the output file by timestamp
    with open(output, 'r') as f:
        lines = f.readlines()
        header = lines[0]
        lines = lines[1:]
        lines.sort(key=lambda x: float(x.split(',')[2]))
        lines.insert(0, header)
    
    with open(output, 'w') as f:
        f.writelines(lines)

    print('Output file:', output)