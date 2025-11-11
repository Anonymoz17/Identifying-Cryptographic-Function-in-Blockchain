"""
file_operations.py - Non-crypto file handling for testing

This script demonstrates typical file operations WITHOUT cryptography.
Static analysis should NOT detect any crypto operations here.
Dynamic analysis won't run this (it's source code).

Run with: python file_operations.py
"""

import os
import json
import csv
from datetime import datetime
from typing import Dict, List

def read_json_file(filepath: str) -> Dict:
    """Read and parse JSON file."""
    print(f"Reading JSON: {filepath}")
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
        print(f"  ✓ Loaded {len(data)} items")
        return data
    except FileNotFoundError:
        print(f"  ✗ File not found")
        return {}

def write_json_file(filepath: str, data: Dict) -> bool:
    """Write data to JSON file."""
    print(f"Writing JSON: {filepath}")
    try:
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"  ✓ File written successfully")
        return True
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return False

def process_csv(filepath: str) -> List[Dict]:
    """Process CSV file."""
    print(f"Processing CSV: {filepath}")
    rows = []
    
    try:
        with open(filepath, 'r', newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                rows.append(row)
        
        print(f"  ✓ Read {len(rows)} rows")
        return rows
    
    except FileNotFoundError:
        print(f"  ✗ File not found")
        return []

def string_operations() -> str:
    """Perform various string operations."""
    print("\nString Operations:")
    
    text = "The quick brown fox jumps over the lazy dog"
    print(f"  Original: {text}")
    
    # String methods (NOT cryptographic)
    upper = text.upper()
    lower = text.lower()
    reversed_text = text[::-1]
    split_text = text.split()
    joined = "-".join(split_text)
    
    print(f"  Upper: {upper[:30]}...")
    print(f"  Split: {len(split_text)} words")
    print(f"  Joined: {joined[:30]}...")
    
    return text

def data_structure_operations() -> Dict:
    """Work with data structures."""
    print("\nData Structure Operations:")
    
    # Create dictionary
    person = {
        "name": "Alice",
        "age": 30,
        "email": "alice@example.com",
        "created": datetime.now().isoformat()
    }
    
    print(f"  Created person: {person['name']}")
    
    # Create list
    items = ["item1", "item2", "item3", "item4"]
    print(f"  Created list: {len(items)} items")
    
    # Perform operations
    items.append("item5")
    items.sort()
    filtered = [x for x in items if "2" not in x]
    
    print(f"  After operations: {len(filtered)} items")
    
    return person

def file_system_operations() -> None:
    """Demonstrate file system operations."""
    print("\nFile System Operations:")
    
    # Check if directory exists
    test_dir = "test_data"
    if not os.path.exists(test_dir):
        os.makedirs(test_dir)
        print(f"  ✓ Created directory: {test_dir}")
    
    # List files
    try:
        files = os.listdir(".")
        print(f"  ✓ Listed {len(files)} items in current directory")
    except Exception as e:
        print(f"  ✗ Error: {e}")
    
    # Get file info
    if os.path.exists(__file__):
        size = os.path.getsize(__file__)
        print(f"  ✓ Current file size: {size} bytes")

def main():
    """Main function demonstrating file operations."""
    print("=" * 50)
    print("File Operations Module - Static Analysis Test")
    print("=" * 50)
    print()
    
    try:
        # Run demonstrations
        string_operations()
        data_structure_operations()
        file_system_operations()
        
        print("\n" + "=" * 50)
        print("Summary")
        print("=" * 50)
        print("✓ JSON operations completed")
        print("✓ CSV processing ready")
        print("✓ String manipulations completed")
        print("✓ Data structures processed")
        print("✓ File system operations completed")
        print("\nStatic analysis should NOT flag any crypto operations!")
        print("This file uses only standard library functions.")
        
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
