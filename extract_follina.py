import argparse
import zipfile
import xml.etree.ElementTree as ET
import re


def decode_docx(file):
    potential_hits = []

    zip = zipfile.ZipFile(file)
    template = zip.read('word/_rels/document.xml.rels')

    xml_root = ET.fromstring(template)
    for xml_node in xml_root.iter():
        target = xml_node.attrib.get('Target')
        if target:
            target = target.lower()
            potential_hits += re.findall(r'mhtml:(https?://.*?)!', target)

    return potential_hits


def decode_rtf(file):
    with open(file, 'r') as f:
        data = f.read()
        f.close()

        potential_hits = re.findall(r'objclass (https?://.*?)}', data)
    return potential_hits


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Extract payload from Follina (CVE-2022-30190) Document')
    parser.add_argument('-f', '--file', dest='file_path', type=str, required=True, help='path to infected docx or rtf')
    args = parser.parse_args()

    file = args.file_path
    ext = file.rsplit('.', 1)

    if len(ext) <= 1 or (ext[1].lower() != 'docx' and ext[1].lower() != 'rtf'):
        raise RuntimeError("invalid file extension (must be rtf or docx)")

    if ext[1].lower() == 'docx':
        hits = decode_docx(file)
    else:
        hits = decode_rtf(file)

    for hit in hits:
        print('found potential hit: ' + hit)


