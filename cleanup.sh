#!/bin/bash
# Cleanup script for PyTorShare project

echo "Cleaning up project directory..."

# Remove __pycache__
rm -rf __pycache__

# Remove stray files
rm -f downloaded.txt.sig "SYNOPSIS_FORMAT is.docx"

# Remove temporary generated files
rm -f encrypted_blob.bin encrypted_aes_key.bin local_url.txt onion_address.txt

# Remove test files
rm -f test.txt *.enc

echo "Cleanup complete!"
echo ""
echo "Clean project structure:"
ls -1

