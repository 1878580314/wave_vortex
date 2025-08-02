#!/bin/bash

set -e


echo "Building WebAssembly package..."
wasm-pack build --target web


echo "Creating public output directory..."
mkdir -p public

echo "Moving assets to public directory..."
mv pkg public/      
cp index.html public/ 

echo "Build complete. Output is in /public directory."