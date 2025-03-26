#!/usr/bin/env python3
import sys
import re
from colorama import Fore, Style, init

init(autoreset=True)

class PEASAnalyzer:
    def __init__(self):
        self.suggestions = []
        self.linux_patterns = {
            'SUID': r'SUID.*found',
            'Capabilities': r'Capabilities.*found',
            'Cron': r'Cron jobs.*found',
            'Sudo': r'Sudo version.*|Sudo rights.*',
            'Writable': r'Writable.*found',
            'Passwords': r'Searching.*passwords.*',
            'Docker': r'Docker.*version.*|docker.*group.*',
            'Kernel': r'Linux version.*|Kernel version.*'
        }
        self.windows_patterns = {
            'Services': r'Services.*vulnerable.*|Unquoted.*Service.*',
            'AlwaysInstallElevated': r'AlwaysInstallElevated.*enabled.*',
            'RegistrySecrets': r'Searching.*registry.*passwords.*',
            'WeakPermissions': r'Permissions.*vulnerable.*|Access.*vulnerable.*',
            'AutoRuns': r'Checking.*AutoRuns.*',
            'Passwords': r'Looking.*stored.*passwords.*',
            'TokenPrivileges': r'Token.*Privileges.*enabled.*',
            'UAC': r'UAC.*settings.*|UAC.*bypass.*'
        }

    def detect_os(self, content):
        return 'windows' if 'Windows' in content[:1000] else 'linux'

    def analyze_file(self, filename):
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            os_type = self.detect_os(content)
            patterns = self.windows_patterns if os_type == 'windows' else self.linux_patterns
            
            for category, pattern in patterns.items():
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    context = self._get_context(content, match.start(), 3)
                    if any(keyword in context.lower() for keyword in ['vulnerable', 'writable', 'warning', 'enabled']):
                        self.suggestions.append({
                            'category': category,
                            'finding': context.strip(),
                            'priority': self._calculate_priority(context),
                            'os_type': os_type
                        })

        except FileNotFoundError:
            print(f"{Fore.RED}Error: File {filename} not found")
            sys.exit(1)

    def _get_context(self, content, pos, lines=3):
        start = max(0, content.rfind('\n', 0, pos) - lines * 80)
        end = content.find('\n', pos + 80)
        return content[start:end]

    def _calculate_priority(self, context):
        if any(word in context.lower() for word in ['critical', 'vulnerable', 'enabled', 'password']):
            return 'HIGH'
        elif any(word in context.lower() for word in ['warning', 'writable', 'weak']):
            return 'MEDIUM'
        return 'LOW'

    def print_suggestions(self):
        if not self.suggestions:
            print(f"{Fore.YELLOW}No significant privilege escalation vectors found.")
            return

        os_type = self.suggestions[0]['os_type'].upper()
        print(f"\n{Fore.GREEN}=== {os_type} Privilege Escalation Suggestions ===\n")
        
        for priority in ['HIGH', 'MEDIUM', 'LOW']:
            findings = [s for s in self.suggestions if s['priority'] == priority]
            if findings:
                print(f"\n{Fore.YELLOW}[{priority} Priority Findings]")
                for finding in findings:
                    print(f"\n{Fore.CYAN}Category: {finding['category']}")
                    print(f"{Fore.WHITE}{finding['finding']}")
                    print("-" * 80)

def main():
    if len(sys.argv) != 2:
        print(f"{Fore.RED}Usage: {sys.argv[0]} <peas_output_file>")
        sys.exit(1)

    analyzer = PEASAnalyzer()
    analyzer.analyze_file(sys.argv[1])
    analyzer.print_suggestions()

if __name__ == "__main__":
    main()