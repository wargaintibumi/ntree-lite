══════════════════════════════════════════════════════════════════════════════
                        NTREE SCOPE TEMPLATES
══════════════════════════════════════════════════════════════════════════════

These template files help you quickly set up penetration testing scopes.
Copy and edit the appropriate template for your engagement.

──────────────────────────────────────────────────────────────────────────────
AVAILABLE TEMPLATES
──────────────────────────────────────────────────────────────────────────────

SCOPE FILES:

  scope_example.txt           Main example with all syntax options explained
  scope_single_target.txt     Single host or application testing
  scope_internal_network.txt  Corporate internal network assessment
  scope_external.txt          Internet-facing assets / attack surface
  scope_active_directory.txt  Windows AD environment testing
  scope_webapp.txt            Web application security testing
  scope_ctf_lab.txt           CTF challenges / home lab / HackTheBox

RULES OF ENGAGEMENT:

  roe_example.txt             Complete ROE template with all options

──────────────────────────────────────────────────────────────────────────────
QUICK START
──────────────────────────────────────────────────────────────────────────────

1. Copy the appropriate template:
   cp templates/scope_single_target.txt my_scope.txt

2. Edit with your targets:
   nano my_scope.txt

3. Run the pentest:
   ./start_pentest.sh --scope my_scope.txt

──────────────────────────────────────────────────────────────────────────────
SCOPE FILE SYNTAX
──────────────────────────────────────────────────────────────────────────────

# Comments start with hash
192.168.1.100              # Single IP address
192.168.1.0/24             # CIDR range (network block)
example.com                # Domain name
*.example.com              # Wildcard (all subdomains)
EXCLUDE 192.168.1.1        # Exclude specific target

──────────────────────────────────────────────────────────────────────────────
EXAMPLES BY SCENARIO
──────────────────────────────────────────────────────────────────────────────

# Quick lab test:
./start_pentest.sh --scope templates/scope_ctf_lab.txt --mode sdk

# Full corporate pentest:
./start_pentest.sh --scope templates/scope_internal_network.txt \
                   --roe templates/roe_example.txt \
                   --iterations 100

# Web app assessment:
./start_pentest.sh --scope templates/scope_webapp.txt --mode api

# Interactive learning:
./start_pentest.sh --scope templates/scope_single_target.txt --mode interactive

══════════════════════════════════════════════════════════════════════════════
IMPORTANT REMINDER
══════════════════════════════════════════════════════════════════════════════

Only test systems you have WRITTEN AUTHORIZATION to test!
Unauthorized access to computer systems is illegal.

══════════════════════════════════════════════════════════════════════════════
