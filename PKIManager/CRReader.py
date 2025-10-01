import json

def CRRReader(file_path, id):
    with open(file_path, 'r') as file:
        data = json.load(file)
    id = str(id)
    credentials = data['vehicles'].get(id, None)
    return credentials

