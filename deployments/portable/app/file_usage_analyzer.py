#!/usr/bin/env python3
"""
File Usage Analyzer - Find unused files in the project
"""

import os
import re
from pathlib import Path
from collections import defaultdict

class FileUsageAnalyzer:
    def __init__(self):
        self.root_dir = Path(__file__).parent.parent.parent  # Go to project root
        self.used_files = set()
        self.import_patterns = []
        self.launcher_references = set()
        
    def analyze_imports(self):
        """Analyze all Python imports"""
        print("🔍 Analyzing Python imports...")
        
        for py_file in self.root_dir.rglob("*.py"):
            if '.git' in str(py_file) or '__pycache__' in str(py_file):
                continue
                
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                # Find import statements
                import_matches = re.findall(r'from\s+([.\w]+)\s+import|import\s+([.\w]+)', content)
                for match in import_matches:
                    module = match[0] or match[1]
                    if module:
                        # Convert module path to file path
                        potential_files = [
                            f"{module.replace('.', '/')}.py",
                            f"{module.replace('.', '/')}//__init__.py"
                        ]
                        for pf in potential_files:
                            full_path = self.root_dir / pf
                            if full_path.exists():
                                self.used_files.add(str(full_path))
                
                # Find local imports (relative paths)
                local_imports = re.findall(r'from\s+([.\w]+)\s+import|import\s+([.\w]+)', content)
                for match in local_imports:
                    module = match[0] or match[1]
                    if module and not module.startswith('.'):
                        # Check if it's a local file
                        local_file = py_file.parent / f"{module}.py"
                        if local_file.exists():
                            self.used_files.add(str(local_file))
                            
            except Exception as e:
                print(f"Warning: Could not read {py_file}: {e}")
    
    def analyze_launchers(self):
        """Analyze batch file references"""
        print("🚀 Analyzing launcher references...")
        
        for bat_file in self.root_dir.rglob("*.bat"):
            if '.git' in str(bat_file):
                continue
                
            try:
                with open(bat_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                # Find Python file references
                py_refs = re.findall(r'python\s+([^\s]+\.py)', content)
                for ref in py_refs:
                    # Convert relative path to absolute
                    ref_path = bat_file.parent / ref
                    if ref_path.exists():
                        self.used_files.add(str(ref_path.resolve()))
                        
            except Exception as e:
                print(f"Warning: Could not read {bat_file}: {e}")
    
    def find_main_entry_points(self):
        """Find main entry points that are definitely used"""
        print("🎯 Finding main entry points...")
        
        # Known main files
        main_files = [
            "web_dashboard_real.py",
            "web_dashboard_enhanced.py", 
            "web_dashboard.py",
            "real_ids_engine.py",
            "working_ids.py",
            "project_debugger.py",
            "project_optimizer.py",
            "health_check.py",
            "port_check.py",
            "simple_dashboard.py",
            "test_dashboard.py"
        ]
        
        for main_file in main_files:
            for file_path in self.root_dir.rglob(main_file):
                if '.git' not in str(file_path):
                    self.used_files.add(str(file_path))
    
    def find_template_references(self):
        """Find template file references"""
        print("🎨 Finding template references...")
        
        for py_file in self.root_dir.rglob("*.py"):
            if '.git' in str(py_file):
                continue
                
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                # Find render_template calls
                template_refs = re.findall(r"render_template\(['\"]([^'\"]+)['\"]", content)
                for ref in template_refs:
                    # Look for template file
                    template_path = py_file.parent / "templates" / ref
                    if template_path.exists():
                        self.used_files.add(str(template_path))
                        
            except Exception as e:
                pass
    
    def get_all_files(self):
        """Get all relevant files in the project"""
        all_files = set()
        
        extensions = ['.py', '.bat', '.md', '.json', '.html']
        
        for ext in extensions:
            for file_path in self.root_dir.rglob(f"*{ext}"):
                if '.git' not in str(file_path) and '__pycache__' not in str(file_path):
                    all_files.add(str(file_path))
        
        return all_files
    
    def identify_unused_files(self):
        """Identify files that appear to be unused"""
        print("\n" + "="*60)
        print("📋 FILE USAGE ANALYSIS REPORT")
        print("="*60)
        
        # Run all analysis methods
        self.find_main_entry_points()
        self.analyze_imports()
        self.analyze_launchers()
        self.find_template_references()
        
        # Get all files
        all_files = self.get_all_files()
        
        # Find unused files
        unused_files = all_files - self.used_files
        
        print(f"\n📊 STATISTICS:")
        print(f"   Total files found: {len(all_files)}")
        print(f"   Files in use: {len(self.used_files)}")
        print(f"   Potentially unused: {len(unused_files)}")
        
        # Categorize unused files
        categories = {
            'Test files': [],
            'Debug files': [],
            'Documentation': [],
            'Config files': [],
            'Other Python files': [],
            'Batch files': [],
            'Unknown': []
        }
        
        for unused_file in unused_files:
            file_path = Path(unused_file)
            file_name = file_path.name.lower()
            
            if 'test' in file_name or 'verify' in file_name:
                categories['Test files'].append(unused_file)
            elif 'debug' in file_name:
                categories['Debug files'].append(unused_file)
            elif file_name.endswith('.md') or 'doc' in file_name:
                categories['Documentation'].append(unused_file)
            elif file_name.endswith('.json') or 'config' in file_name:
                categories['Config files'].append(unused_file)
            elif file_name.endswith('.py'):
                categories['Other Python files'].append(unused_file)
            elif file_name.endswith('.bat'):
                categories['Batch files'].append(unused_file)
            else:
                categories['Unknown'].append(unused_file)
        
        # Display results by category
        print(f"\n🗂️ UNUSED FILES BY CATEGORY:")
        for category, files in categories.items():
            if files:
                print(f"\n📁 {category} ({len(files)} files):")
                for file_path in sorted(files):
                    rel_path = Path(file_path).relative_to(self.root_dir)
                    print(f"   • {rel_path}")
        
        # Recommendations
        print(f"\n💡 RECOMMENDATIONS:")
        
        safe_to_remove = []
        review_needed = []
        
        for category, files in categories.items():
            if category in ['Test files', 'Debug files'] and files:
                print(f"   🔸 {category}: Review if still needed for development")
                review_needed.extend(files)
            elif category == 'Documentation' and files:
                print(f"   📚 {category}: Keep unless outdated")
            elif category == 'Config files' and files:
                print(f"   ⚙️ {category}: Review - may be used indirectly")
                review_needed.extend(files)
            elif category in ['Other Python files', 'Batch files'] and files:
                print(f"   ⚠️ {category}: Careful review needed")
                review_needed.extend(files)
        
        return {
            'unused_files': unused_files,
            'categories': categories,
            'safe_to_remove': safe_to_remove,
            'review_needed': review_needed
        }

def main():
    analyzer = FileUsageAnalyzer()
    results = analyzer.identify_unused_files()
    
    print(f"\n🎯 SUMMARY:")
    print(f"   Files that may be safe to remove: {len(results['safe_to_remove'])}")
    print(f"   Files needing review: {len(results['review_needed'])}")
    
    # Save detailed report
    report_path = Path(__file__).parent / 'file_usage_report.json'
    import json
    
    # Convert Path objects to strings for JSON serialization
    json_data = {
        'unused_files': list(results['unused_files']),
        'categories': {k: list(v) for k, v in results['categories'].items()},
        'analysis_summary': {
            'total_unused': len(results['unused_files']),
            'safe_to_remove': len(results['safe_to_remove']),
            'review_needed': len(results['review_needed'])
        }
    }
    
    with open(report_path, 'w') as f:
        json.dump(json_data, f, indent=2)
    
    print(f"\n📄 Detailed report saved to: {report_path}")

if __name__ == "__main__":
    main()
