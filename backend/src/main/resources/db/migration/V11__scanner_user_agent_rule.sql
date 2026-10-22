INSERT INTO alert_rule (name, description, severity, expression)
VALUES (
    'scanner-user-agent',
    'Scanner User-Agent: an attack tool such as sqlmap, Nikto or Nmap, an attack payload such as'
        || ' a Log4Shell JNDI lookup or Shellshock in the header, or a command-line client such as'
        || ' curl or Wget whose request was answered with a 4xx or 5xx.',
    'WARNING',
    'userAgent matches "(?i)\b(?:sqlmap|nikto|nmap|masscan|zgrab|zmap|nuclei|wpscan|joomscan'
        || '|droopescan|dirbuster|dirb|gobuster|feroxbuster|ffuf|fuzz faster u fool|wfuzz|acunetix'
        || '|netsparker|nessus|openvas|w3af|arachni|skipfish|whatweb|havij|commix|fimap|xsser|jaeles'
        || '|hydra|zmeu|morfeus)\b"'
        || ' or userAgent matches "(?i)\(\s*+\)\s*+\{'
        || '|\$\{(?:jndi|[$:]|(?:lower|upper|env|sys|date|base64|main|ctx)\b)'
        || '|<script\b|\bunion\s++(?:all\s++)?select\b|\b(?:sleep|pg_sleep|benchmark)\s*+\(\s*+\d'
        || '|\.\./"'
        || ' or userAgent matches "(?i)\b(?:curl|wget|python-requests|python-urllib|python-httpx'
        || '|aiohttp|go-http-client|libwww-perl|lwp-trivial|windowspowershell|httpie|java/\d)"'
        || ' and status >= 400'
)
ON CONFLICT (name) DO NOTHING;
