import os
from http_scan import HttpScanner






def validate_input_file(filepath):
    if not os.path.exists(filepath):
        raise ValueError("Input file does not exist")
    with open(filepath) as f:
        for line in f:
            if not line.strip():
                continue
            if len(line.split()) != 2:
                raise ValueError(f"Invalid input format: {line}")
            hostname, ip = line.strip().split()
            if not hostname or not ip:
                raise ValueError(f"Invalid input format: {line}")




def report_zap(filepath):
    my_zap = HttpScanner()
    my_zap.get_path()
    validate_input_file(filepath)
    my_zap.create_excel_sheets()
    my_zap.create_word()

def main():
    filepath = "list.txt"
    report_zap(filepath)



if __name__ == '__main__':
    main()
