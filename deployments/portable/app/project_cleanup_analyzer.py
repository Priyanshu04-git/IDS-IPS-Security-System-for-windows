#!/usr/bin/env python3
"""
Project-specific file cleanup analysis
Focus on actual project files that may be unused
"""

import os
from pathlib import Path

def analyze_project_files():
    """Analyze only project-specific files for cleanup"""
    
    project_root = Path(__file__).parent.parent.parent
    app_dir = Path(__file__).parent
    
    print("🔍 ANALYZING PROJECT-SPECIFIC FILES")
    print("=" * 50)
    
    # Files that are potentially unused based on our analysis
    potentially_unused = [
        # Test files in our project
        "test_correct_threats.py",
        "test_trigger_threats.py", 
        "test_threats.py",
        "verify_fixes.py",
        
        # Debug files that may no longer be needed
        "debug_threats.py",
        "debug_connections.py",
        "debug_report.json",
        
        # Other files to check
        "signatures.json",
    ]
    
    # Files in src/ directory that might be duplicates
    src_files = [
        "src/core/main_windows.py",
        "src/core/data_manager.py", 
        "src/core/real_ids_engine.py",
        "src/core/working_ids.py",
        "src/detection/",
        "src/prevention/",
        "src/utils/",
    ]
    
    print("📋 FILES TO REVIEW FOR REMOVAL:")
    print()
    
    print("🧪 TEST FILES (consider removing if no longer needed):")
    for file in potentially_unused[:4]:  # First 4 are test files
        file_path = app_dir / file
        if file_path.exists():
            size = file_path.stat().st_size
            print(f"   • {file} ({size} bytes)")
        else:
            print(f"   • {file} (not found)")
    
    print()
    print("🐛 DEBUG FILES (review if still needed for development):")
    for file in potentially_unused[4:7]:  # Debug files
        file_path = app_dir / file
        if file_path.exists():
            size = file_path.stat().st_size
            print(f"   • {file} ({size} bytes)")
        else:
            print(f"   • {file} (not found)")
    
    print()
    print("📁 SRC DIRECTORY ANALYSIS:")
    src_dir = project_root / "src"
    if src_dir.exists():
        print(f"   The src/ directory exists with the following structure:")
        for item in src_dir.rglob("*"):
            if item.is_file() and item.suffix in ['.py', '.md']:
                rel_path = item.relative_to(project_root)
                print(f"   • {rel_path}")
        print(f"   NOTE: src/ may be redundant since we have deployments/portable/")
    else:
        print("   ✅ src/ directory has been removed")
    
    print()
    print("🎯 RECOMMENDATIONS:")
    print()
    
    # Test files
    print("1. TEST FILES:")
    print("   • test_correct_threats.py - Remove if testing is complete")
    print("   • test_trigger_threats.py - Remove if testing is complete") 
    print("   • test_threats.py - Remove if testing is complete")
    print("   • verify_fixes.py - Remove if verification is complete")
    
    print()
    print("2. DEBUG FILES:")
    print("   • debug_threats.py - Keep if still debugging, remove if stable")
    print("   • debug_connections.py - Keep if still debugging, remove if stable")
    print("   • debug_report.json - Can be regenerated, safe to remove")
    
    print()
    print("3. CONFIG FILES:")
    print("   • signatures.json - Keep if used by detection engines")
    
    print()
    print("4. SRC DIRECTORY:")
    if src_dir.exists():
        print("   • Consider removing entire src/ directory if deployments/portable/ is the main version")
    
    print()
    print("5. OTHER CLEANUP:")
    print("   • Check for any __pycache__ directories")
    print("   • Check for any .pyc files")
    print("   • Check for any temporary files")
    
    return potentially_unused

def check_file_usage(files_to_check):
    """Check if files are actually referenced anywhere"""
    
    app_dir = Path(__file__).parent
    project_root = app_dir.parent.parent.parent
    
    print("\n🔍 CHECKING FILE REFERENCES:")
    print("=" * 30)
    
    for file_name in files_to_check:
        file_path = app_dir / file_name
        if not file_path.exists():
            continue
            
        print(f"\n📄 {file_name}:")
        
        # Check if file is imported or referenced
        references_found = False
        
        # Search in Python files
        for py_file in app_dir.glob("*.py"):
            if py_file.name == file_name:
                continue
                
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                # Check for imports or references
                module_name = file_name.replace('.py', '')
                if (f"import {module_name}" in content or 
                    f"from {module_name}" in content or
                    f'"{file_name}"' in content or
                    f"'{file_name}'" in content):
                    print(f"   ✅ Referenced in {py_file.name}")
                    references_found = True
                    
            except Exception:
                pass
        
        # Check in batch files
        for bat_file in project_root.rglob("*.bat"):
            if '.git' in str(bat_file):
                continue
                
            try:
                with open(bat_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                if file_name in content:
                    print(f"   ✅ Referenced in {bat_file.name}")
                    references_found = True
                    
            except Exception:
                pass
        
        if not references_found:
            print(f"   ❌ No references found - SAFE TO REMOVE")
        
    return references_found

def main():
    files = analyze_project_files()
    check_file_usage(files)
    
    print("\n" + "=" * 50)
    print("🎯 SUMMARY:")
    print("Files marked as 'SAFE TO REMOVE' have no detected references")
    print("Review each file before deletion to ensure it's not needed")
    print("Consider keeping debug files if you're still developing")

if __name__ == "__main__":
    main()
