"""User-created rules.

Custom rules are not code: they are validated rule definitions (the same condition
language as the built-in rules) stored in triage.db and loaded by the detection
service at start-up (engine/service.py, _load_custom_rules).  They are kept apart from
imported rules, marked 'User-defined' and never presented as verified.
"""
