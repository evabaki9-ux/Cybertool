"""Manual, read-only guides for each signature in the local list.

These guides explain what a finding means, how to confirm it without attacking
the target, and how to fix it. They deliberately contain no exploit payloads,
credential-attack commands or instructions for executing commands on a host.
"""

from __future__ import annotations

SCOPE_NOTE = (
    "Only follow this on systems you own or have written permission to test. "
    "Stop if you are unsure about authorization."
)

GENERIC = {
    "overview": "This signature matched a service property reported by the port scan.",
    "safe_steps": [
        "Use the Verify safely button to re-read the service banner.",
        "Compare the reported version with your package or vendor advisory.",
        "Review service logs for unexpected connections around the scan time.",
    ],
    "fix_steps": [
        "Upgrade the affected software to a currently supported release.",
        "Restrict access to trusted networks and remove unnecessary exposure.",
    ],
    "references": [],
}

GUIDES = {
    "vsftpd-234-backdoor": {
        "overview": "A backdoor existed in one specific vsftpd release. Matching the version banner confirms the build, not that the backdoor is active.",
        "safe_steps": [
            "Confirm the running version with the Verify safely button.",
            "Check your package manager to see which upstream build is installed.",
            "Review FTP logs for unexpected connections from unfamiliar addresses.",
        ],
        "fix_steps": [
            "Upgrade vsftpd to a current release from your operating system vendor.",
            "Restrict port 21 to trusted networks and disable anonymous access where it is not needed.",
        ],
        "references": ["CVE-2011-2523", "https://nvd.nist.gov/vuln/detail/CVE-2011-2523"],
    },
    "openssh-user-enumeration": {
        "overview": "Older OpenSSH builds can reveal whether a username exists through timing differences in authentication.",
        "safe_steps": [
            "Confirm the SSH version with the Verify safely button.",
            "Review authentication logs for repeated failed usernames.",
            "Check whether password authentication is currently enabled.",
        ],
        "fix_steps": [
            "Upgrade OpenSSH through your OS package manager.",
            "Set PasswordAuthentication no and use key-based authentication.",
            "Rate-limit connections to port 22 with a firewall or fail2ban.",
        ],
        "references": ["CVE-2016-6210", "https://nvd.nist.gov/vuln/detail/CVE-2016-6210"],
    },
    "apache-path-traversal": {
        "overview": "Two Apache releases had a path traversal flaw affecting certain CGI and alias configurations. A version match is not proof the server is misconfigured.",
        "safe_steps": [
            "Confirm the Apache version from the Verify safely result.",
            "Review access logs for unusual encoded request paths.",
            "Check whether mod_cgi and broad Alias directives are enabled.",
        ],
        "fix_steps": [
            "Upgrade to Apache 2.4.51 or later from your vendor.",
            "Review Alias and CGI configuration and remove unnecessary directives.",
        ],
        "references": ["CVE-2021-41773", "CVE-2021-42013"],
    },
    "tomcat-ghostcat": {
        "overview": "Some Tomcat versions exposed the AJP connector. Risk depends on whether AJP is reachable and how it is configured.",
        "safe_steps": [
            "Confirm the Tomcat version with the Verify safely button.",
            "Check whether the AJP connector is bound to a public interface.",
            "Review the connector configuration for a required secret.",
        ],
        "fix_steps": [
            "Upgrade Tomcat to a supported patched release.",
            "Disable AJP if it is unused, or require a secret and bind it privately.",
        ],
        "references": ["CVE-2020-1938", "https://nvd.nist.gov/vuln/detail/CVE-2020-1938"],
    },
    "smb-ms17010": {
        "overview": "Unpatched SMBv1 systems were affected by a wormable remote code execution flaw. Patch level cannot be read anonymously.",
        "safe_steps": [
            "Confirm the SMB service is present using the Verify safely button.",
            "Check the host's installed updates through your authorized management channel.",
            "Review SMB logs for unusual remote access.",
        ],
        "fix_steps": [
            "Apply MS17-010 through your operating system update mechanism.",
            "Disable SMBv1 and block port 445 at the network boundary.",
        ],
        "references": ["MS17-010", "CVE-2017-0144"],
    },
    "rdp-bluekeep": {
        "overview": "Older Windows Remote Desktop builds were affected by a pre-authentication flaw. The OS version cannot be confirmed without an authenticated check.",
        "safe_steps": [
            "Confirm the RDP service is present with the Verify safely button.",
            "Check the host's patch level through your authorized management channel.",
            "Review Remote Desktop logs for unexpected connection attempts.",
        ],
        "fix_steps": [
            "Apply the CVE-2019-0708 update from Microsoft.",
            "Enable network level authentication and restrict port 3389 to trusted IPs.",
        ],
        "references": ["CVE-2019-0708", "https://nvd.nist.gov/vuln/detail/CVE-2019-0708"],
    },
    "redis-open": {
        "overview": "Redis is designed to be run on a trusted network. Exposure depends on authentication and protected-mode settings.",
        "safe_steps": [
            "Confirm the service is reachable with the Verify safely button.",
            "Using an account you control, check whether authentication is required.",
            "Review Redis logs for connections from unfamiliar addresses.",
        ],
        "fix_steps": [
            "Enable AUTH and protected-mode.",
            "Bind Redis to a private interface and firewall port 6379.",
        ],
        "references": ["CWE-306"],
    },
    "mongodb-open": {
        "overview": "MongoDB exposure depends on whether authentication is enabled and which interfaces it listens on.",
        "safe_steps": [
            "Confirm the service is reachable with the Verify safely button.",
            "Check authentication settings using your own administrative access.",
            "Review database logs for unexpected client addresses.",
        ],
        "fix_steps": [
            "Enable authentication and least-privilege users.",
            "Bind to a private interface and firewall port 27017.",
        ],
        "references": ["CWE-306"],
    },
    "elasticsearch-open": {
        "overview": "An exposed search API can reveal indexed documents and allow cluster changes if security features are off.",
        "safe_steps": [
            "Confirm the service is reachable with the Verify safely button.",
            "Check whether security features are enabled using your own credentials.",
            "Review access logs for unknown source addresses.",
        ],
        "fix_steps": [
            "Enable Elasticsearch security features and TLS.",
            "Bind privately and place the API behind an authenticated proxy.",
        ],
        "references": ["CWE-306"],
    },
    "docker-daemon-open": {
        "overview": "A Docker API without TLS authentication can grant control of the host to anyone who can reach the socket.",
        "safe_steps": [
            "Confirm the port is reachable with the Verify safely button.",
            "Check your daemon configuration for TLS mutual authentication.",
            "Review Docker logs for unexpected API clients.",
        ],
        "fix_steps": [
            "Close port 2375 and use a TLS-protected socket on 2376.",
            "Restrict access to the daemon to trusted hosts only.",
        ],
        "references": ["CWE-306"],
    },
    "jenkins-open": {
        "overview": "An unauthenticated Jenkins console can allow anyone to run jobs on build agents.",
        "safe_steps": [
            "Confirm the service is reachable with the Verify safely button.",
            "Check whether authentication is enabled in Jenkins configuration.",
            "Review build history for jobs you do not recognise.",
        ],
        "fix_steps": [
            "Enable authentication and authorisation.",
            "Restrict the console behind a VPN or authenticated reverse proxy.",
        ],
        "references": ["CWE-306"],
    },
    "telnet-cleartext": {
        "overview": "Telnet sends credentials and session data without encryption.",
        "safe_steps": [
            "Confirm the Telnet service is present with the Verify safely button.",
            "Check whether SSH is available as a replacement.",
            "Review network policy for who is allowed to reach port 23.",
        ],
        "fix_steps": ["Disable Telnet and migrate users to SSH.", "Firewall port 23."],
        "references": ["CWE-319"],
    },
    "vnc-cleartext": {
        "overview": "VNC sessions may be unencrypted and protected only by a short password.",
        "safe_steps": [
            "Confirm the VNC service is present with the Verify safely button.",
            "Check whether the session is tunneled through SSH or TLS.",
            "Review VNC logs for unfamiliar connections.",
        ],
        "fix_steps": [
            "Tunnel VNC over SSH or TLS.",
            "Use strong authentication and firewall port 5900.",
        ],
        "references": ["CWE-319"],
    },
    "snmp-default": {
        "overview": "SNMP with default community strings can disclose system and network information.",
        "safe_steps": [
            "Confirm the SNMP service is present with the Verify safely button.",
            "Check which SNMP version and community strings are configured.",
            "Review allowed source addresses in your network policy.",
        ],
        "fix_steps": [
            "Use SNMPv3 with authentication and encryption.",
            "Replace default community strings and restrict source IPs.",
        ],
        "references": ["CWE-1188"],
    },
    "ftp-cleartext": {
        "overview": "Plain FTP transmits credentials in cleartext and may allow anonymous access.",
        "safe_steps": [
            "Confirm the FTP service is present with the Verify safely button.",
            "Check whether anonymous access is enabled.",
            "Review FTP logs for unexpected logins.",
        ],
        "fix_steps": [
            "Move to SFTP or FTPS.",
            "Disable anonymous access and restrict source IPs.",
        ],
        "references": ["CWE-319"],
    },
    "memcached-open": {
        "overview": "An exposed Memcached instance may leak cached data and can be abused for amplification.",
        "safe_steps": [
            "Confirm the service is present with the Verify safely button.",
            "Check whether it is bound to a private interface and whether UDP is disabled.",
            "Review source addresses in Memcached logs.",
        ],
        "fix_steps": [
            "Bind to localhost and disable UDP.",
            "Firewall port 11211 from untrusted networks.",
        ],
        "references": ["CWE-306"],
    },
}


def guide_for(finding_id: str) -> dict:
    """Return a manual guide for a signature id, with a safe generic fallback."""
    guide = GUIDES.get(str(finding_id), GENERIC)
    return {
        "finding_id": finding_id,
        "overview": guide["overview"],
        "safe_steps": list(guide["safe_steps"]),
        "fix_steps": list(guide["fix_steps"]),
        "references": list(guide["references"]),
        "scope_note": SCOPE_NOTE,
        "contains_exploit_instructions": False,
    }
