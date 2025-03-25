#!/bin/bash

# Define the folder structure
mkdir -p static/css static/js static/images static/pdf
mkdir -p templates
mkdir -p uploads

# Create required files
touch static/css/style.css
touch static/js/script.js
touch static/images/logo.png
touch static/pdf/cybersecurity_ppt.pdf

touch templates/base.html
touch templates/index.html
touch templates/password_checker.html
touch templates/encryption.html
touch templates/decryption.html
touch templates/awareness.html
touch templates/dos_donts.html
touch templates/attacks.html
touch templates/ppt.html

echo "Folder structure and files created successfully!"

