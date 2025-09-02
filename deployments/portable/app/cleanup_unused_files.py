#!/usr/bin/env python3
"""
Safe File Cleanup Script
Remove confirmed unused files from the project
"""

import os
from pathlib import Path

def remove_unused_files():
    """Remove files that are confirmed to be unused"""
    
    app_dir = Path(__file__).parent
    
    print("🗑️ CLEANING UP UNUSED FILES")
    print("=" * 40)
    
    # Files confirmed as safe to remove
    files_to_remove = [
        "test_threats.py",  # Empty file
        "verify_fixes.py",  # Empty file  
        "debug_report.json",  # Can be regenerated
        # Note: Keeping other files for now until we're 100% sure
    ]
    
    # Files to review but not auto-remove
    files_to_review = [
        "test_correct_threats.py",  # Has content, may be useful
        "test_trigger_threats.py",  # Has content, may be useful
        "debug_threats.py",  # May be useful for debugging
        "debug_connections.py",  # May be useful for debugging
    ]
    
    removed_files = []
    
    print("🔄 REMOVING CONFIRMED UNUSED FILES:")
    for file_name in files_to_remove:
        file_path = app_dir / file_name
        if file_path.exists():
            try:
                file_size = file_path.stat().st_size
                file_path.unlink()
                removed_files.append(file_name)
                print(f"   ✅ Removed {file_name} ({file_size} bytes)")
            except Exception as e:
                print(f"   ❌ Failed to remove {file_name}: {e}")
        else:
            print(f"   ⚠️ {file_name} not found")
    
    print(f"\n📋 FILES KEPT FOR REVIEW:")
    for file_name in files_to_review:
        file_path = app_dir / file_name
        if file_path.exists():
            file_size = file_path.stat().st_size
            print(f"   📄 {file_name} ({file_size} bytes) - Review manually")
    
    print(f"\n🎯 SUMMARY:")
    print(f"   Files removed: {len(removed_files)}")
    print(f"   Files kept for review: {len(files_to_review)}")
    
    if removed_files:
        print(f"\n✅ Removed files: {', '.join(removed_files)}")
    
    return removed_files

def check_other_directories():
    """Check for unused files in other directories"""
    
    project_root = Path(__file__).parent.parent.parent
    
    print(f"\n🔍 CHECKING OTHER DIRECTORIES:")
    print("=" * 30)
    
    # Check if there are any unused directories
    potentially_unused_dirs = [
        "tests",
        "docs/old",
        "config/old", 
        "logs",
        "data"
    ]
    
    for dir_name in potentially_unused_dirs:
        dir_path = project_root / dir_name
        if dir_path.exists():
            file_count = len(list(dir_path.rglob("*")))
            print(f"   📁 {dir_name}/ exists ({file_count} items) - Review contents")
        else:
            print(f"   ✅ {dir_name}/ does not exist")

def main():
    removed_files = remove_unused_files()
    check_other_directories()
    
    print(f"\n" + "=" * 40)
    print("🎯 CLEANUP COMPLETE!")
    
    if removed_files:
        print("✅ Successfully removed unused files")
        print("💡 Consider running git status to see changes")
    else:
        print("ℹ️ No files were removed")
    
    print("🔍 Review remaining files manually before removing")

if __name__ == "__main__":
    main()
