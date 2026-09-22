/**
 * Vulnerability Plain-Language Explainer Library
 * Maps technical vulnerability categories to plain English explanations
 * for users with no cybersecurity background.
 */

export interface VulnExplanation {
  category: string;
  plainName: string;
  emoji: string;
  simpleExplanation: string;
  analogy: string;
  whatWeScanned: string;
  whatWasFound: string;
  realWorldRisk: string;
  whoIsAffected: string;
  whatToDoNext: string[];
  urgency: 'critical' | 'high' | 'medium' | 'low';
}

export const VULN_EXPLANATIONS: Record<string, VulnExplanation> = {
  O1_RCE: {
    category: 'O1_RCE',
    plainName: 'Remote Code Execution (Full System Takeover)',
    emoji: '💣',
    simpleExplanation:
      'The attacker can run any program they want on your server — it\'s like handing them the keys to your data center. They can read all student data, delete files, install ransomware, or spy on everything happening on the server.',
    analogy:
      '🔑 Imagine someone found a hidden door into your school that bypasses all locks. Once inside, they can open any room, change any grade, delete any file, or install cameras everywhere — and you wouldn\'t even know.',
    whatWeScanned:
      'Our tool connected to your website and checked which software versions and frameworks it uses. It then compared these signatures against a database of known vulnerabilities.',
    whatWasFound:
      'A known vulnerability pattern was detected that matches software that can be exploited to execute commands directly on your server. This means a hacker could potentially "speak directly" to the computer running your website and tell it what to do.',
    realWorldRisk:
      '⚠️ CRITICAL: This is the most dangerous type of vulnerability. It can lead to complete database theft (student records, grades, personal information), ransomware attacks that lock your entire system, the system being used to attack other schools or websites, and permanent data deletion.',
    whoIsAffected:
      'All students, faculty, and staff whose data is stored in the system. Also any third parties (parents, government portals) connected to this system.',
    whatToDoNext: [
      'IMMEDIATELY contact your IT team or system administrator — this cannot wait.',
      'Take the affected service offline or firewall it from the internet until patched.',
      'Update the software component identified in the scan report to the latest version.',
      'Check server logs to see if unauthorized access already occurred.',
      'If breach is suspected, notify your institution\'s data protection officer and relevant authorities.',
    ],
    urgency: 'critical',
  },

  O2_SQL_INJECTION: {
    category: 'O2_SQL_INJECTION',
    plainName: 'SQL Injection (Database Theft)',
    emoji: '🗄️',
    simpleExplanation:
      'SQL Injection lets an attacker ask your database questions it was never supposed to answer — and trick it into handing over all stored data. Think: student records, grades, login passwords, personal information.',
    analogy:
      '📋 Imagine a school librarian who follows any written request to the letter. A bad actor writes "Give me ALL the books AND the secret master list of passwords" on the request form. The librarian, following instructions blindly, hands everything over. SQL Injection exploits a similar "trust everything" flaw in databases.',
    whatWeScanned:
      'We tested the web forms and URL parameters on your website by sending specially crafted inputs. We checked whether the system properly validates and blocks dangerous database commands.',
    whatWasFound:
      'The system appears to pass user input directly into database queries without proper filtering. An attacker could craft special input (like entering `\' OR 1=1 --` in a login field) to extract the entire database or bypass login.',
    realWorldRisk:
      'Attackers can extract all student data (names, emails, student IDs, grades), read staff credentials and administrator passwords, bypass login screens without knowing any real password, and modify or delete academic records.',
    whoIsAffected:
      'Every person whose data is in the database — students, staff, faculty. Also the institution if academic records are altered.',
    whatToDoNext: [
      'Use "parameterized queries" or "prepared statements" in your database code — this is the standard fix.',
      'Never build database queries by joining user-typed text directly.',
      'Add a Web Application Firewall (WAF) as an immediate layer of protection.',
      'Audit your login and search forms first — these are the most common attack vectors.',
      'Have a security professional review all database access code.',
    ],
    urgency: 'high',
  },

  O3_WEAK_PASSWORD: {
    category: 'O3_WEAK_PASSWORD',
    plainName: 'Weak / Default Password (Easy Entry)',
    emoji: '🔓',
    simpleExplanation:
      'The system is using well-known default passwords (like "admin/admin123") that anyone who Googles the software can find. This is like leaving your front door unlocked because the original factory key is publicly posted online.',
    analogy:
      '🏠 Imagine buying a brand-new house and the salesperson tells you "the default key is 1234." If you never change it, any burglar who heard that sales pitch can walk straight in.',
    whatWeScanned:
      'We identified the software running on your server. We then checked whether that software\'s widely-known default credentials are still active. We also checked whether the system enforces password complexity rules.',
    whatWasFound:
      'The software identified matches a known pattern of systems deployed with default credentials that are rarely changed. This means simple credentials (e.g., admin/admin123, admin/password) may still grant full administrative access.',
    realWorldRisk:
      'An attacker can log in as an administrator without any advanced hacking skills — just by trying a few well-known default combinations. Once logged in, they have full control of the application, user accounts, and data.',
    whoIsAffected:
      'The entire institution. Default admin access gives control over all user accounts, configurations, and often database access.',
    whatToDoNext: [
      'IMMEDIATELY change all default passwords — especially admin accounts.',
      'Require all users to set strong, unique passwords (minimum 12 characters, mixed case, numbers, symbols).',
      'Enable Multi-Factor Authentication (MFA) for all admin accounts.',
      'Review the list of all user accounts — remove or disable any that are no longer needed.',
      'Set up an account lockout policy after a few failed login attempts.',
    ],
    urgency: 'critical',
  },

  O4_UNAUTHORIZED: {
    category: 'O4_UNAUTHORIZED',
    plainName: 'Unauthorized Access (Locked Door Left Open)',
    emoji: '🚪',
    simpleExplanation:
      'The system has protected pages or features, but a flaw in the "doorman logic" lets attackers bypass the check and walk straight in. They don\'t need a password — just a clever trick in the URL.',
    analogy:
      '🎭 Imagine a nightclub where VIP rooms require a special wristband. But if you enter through the fire exit and say the secret phrase in the URL, the bouncer waves you through. Same level of access, zero credentials.',
    whatWeScanned:
      'We tested whether adding special characters or path modifications to URLs allows access to pages that should require login or administrator rights. We specifically tested against known bypass patterns for the frameworks identified.',
    whatWasFound:
      'The access control mechanism (likely Apache Shiro or a similar authentication framework) contains a known path traversal vulnerability. Adding `/../` or similar tricks to URLs may bypass authentication checks entirely.',
    realWorldRisk:
      'Attackers can access admin control panels without credentials, view private student records and reports, make configuration changes to the system, and potentially gain a foothold for further attacks.',
    whoIsAffected:
      'All users, particularly those whose private data is in sections supposed to be admin-only.',
    whatToDoNext: [
      'Update the authentication framework (e.g., Apache Shiro) to the latest patched version immediately.',
      'Apply a URL normalization rule — strip any `..` or encoded slash sequences before access control checks.',
      'Test all protected pages by trying path variations (add `/`, `../`, `%2f`, etc.) and verify they still reject access.',
      'Audit your access control logic — prefer whitelist (allow specific paths) over blacklist (block specific patterns).',
    ],
    urgency: 'high',
  },

  O5_TOKEN_TAMPERING: {
    category: 'O5_TOKEN_TAMPERING',
    plainName: 'Token / Session Tampering (Fake Identity Badge)',
    emoji: '🎟️',
    simpleExplanation:
      'Your system uses digital "tokens" (like temporary ID badges) to remember who is logged in. If the secret used to stamp these badges is weak or publicly known, attackers can forge their own badge claiming to be any user — including administrators.',
    analogy:
      '🪪 A university ID card says "John Smith, Student." If the lamination machine\'s special ink is just a permanent marker anyone can buy, a bad actor can make a fake card that says "Admin, Super User" and be trusted by every door in the building.',
    whatWeScanned:
      'We checked the system\'s session management and authentication tokens (JWT - JSON Web Tokens). We looked for signs of weak signing secrets, disabled signature verification, or algorithm confusion attacks.',
    whatWasFound:
      'The system uses JWT tokens with indicators suggesting a weak or default secret key. An attacker who discovers or brute-forces this key can forge tokens that grant them any identity in the system — including full administrative access — without ever knowing a password.',
    realWorldRisk:
      'Complete identity theft within the system. Attackers can impersonate any student or administrator, access all their private data, submit false grades, or make administrative changes while appearing to be a legitimate user.',
    whoIsAffected:
      'Every logged-in user. The attacker can impersonate anyone — students, faculty, administrators.',
    whatToDoNext: [
      'Change your JWT secret key immediately to a cryptographically random 256-bit key.',
      'Never use simple secrets like "secret", "password", "123456", or the application name.',
      'Use a key management system or environment variable (not hardcoded in source code).',
      'Ensure JWT signature algorithm is set to HS256 or RS256 — reject "alg: none" tokens.',
      'Rotate all existing tokens (log everyone out and require fresh login) after changing the secret.',
    ],
    urgency: 'critical',
  },

  O6_INFO_DISCLOSURE: {
    category: 'O6_INFO_DISCLOSURE',
    plainName: 'Sensitive Information Disclosure (Leaking Internal Secrets)',
    emoji: '📤',
    simpleExplanation:
      'Your website is accidentally showing private behind-the-scenes information to anyone who visits certain special URLs. This includes things like database passwords, server configuration, internal API keys, and detailed error messages that help attackers plan their next move.',
    analogy:
      '🏢 Imagine a company accidentally posting their internal phone directory, server room access codes, and email passwords on a public notice board — not because they were hacked, but because the sign was always there and nobody noticed.',
    whatWeScanned:
      'We checked commonly exposed endpoints like `/actuator/env`, `/actuator/heapdump`, `/.git/`, `/swagger-ui.html`, `/api-docs`, and error pages. We also checked HTTP response headers for version information leakage.',
    whatWasFound:
      'The system exposes internal management endpoints or configuration APIs that are publicly accessible. These may reveal database connection strings, API keys, internal IP addresses, software versions, and other configuration details that make further attacks much easier.',
    realWorldRisk:
      'While this alone may not compromise the system, attackers use this information to plan more targeted attacks. Database credentials in exposed config can be used to directly connect to your database. Git repositories may contain hardcoded passwords. Detailed errors help attackers craft precise SQL injection or RCE attacks.',
    whoIsAffected:
      'The entire infrastructure — exposed credentials can affect connected systems, APIs, and third-party services.',
    whatToDoNext: [
      'Disable all Spring Boot Actuator endpoints in production OR secure them behind authentication.',
      'Remove or block access to `/.git/` directory on production servers (use `.htaccess` or nginx rules).',
      'Disable Swagger UI / API docs in production environments.',
      'Configure custom error pages that don\'t reveal stack traces or framework versions.',
      'Audit all HTTP response headers — remove `X-Powered-By`, `Server`, and `X-AspNet-Version` headers.',
    ],
    urgency: 'medium',
  },
};

/**
 * Get explanation for a vulnerability by category code or finding title keywords
 */
export function getVulnExplanation(category?: string, title?: string): VulnExplanation | null {
  if (category && VULN_EXPLANATIONS[category]) {
    return VULN_EXPLANATIONS[category];
  }

  // Fallback: match by title keywords
  if (title) {
    const t = title.toLowerCase();
    if (t.includes('sql') || t.includes('injection')) return VULN_EXPLANATIONS['O2_SQL_INJECTION'];
    if (t.includes('rce') || t.includes('remote code') || t.includes('log4j') || t.includes('spring')) return VULN_EXPLANATIONS['O1_RCE'];
    if (t.includes('password') || t.includes('credential') || t.includes('default') || t.includes('weak')) return VULN_EXPLANATIONS['O3_WEAK_PASSWORD'];
    if (t.includes('unauthorized') || t.includes('bypass') || t.includes('shiro') || t.includes('authentication')) return VULN_EXPLANATIONS['O4_UNAUTHORIZED'];
    if (t.includes('token') || t.includes('jwt') || t.includes('session') || t.includes('tampering')) return VULN_EXPLANATIONS['O5_TOKEN_TAMPERING'];
    if (t.includes('disclosure') || t.includes('actuator') || t.includes('swagger') || t.includes('information') || t.includes('git')) return VULN_EXPLANATIONS['O6_INFO_DISCLOSURE'];
  }

  return null;
}

export const URGENCY_CONFIG = {
  critical: { color: '#ef4444', bg: 'rgba(239, 68, 68, 0.08)', border: 'rgba(239, 68, 68, 0.25)', label: 'CRITICAL — Act Now' },
  high: { color: '#f59e0b', bg: 'rgba(245, 158, 11, 0.08)', border: 'rgba(245, 158, 11, 0.25)', label: 'HIGH — Act Soon' },
  medium: { color: '#3b82f6', bg: 'rgba(59, 130, 246, 0.08)', border: 'rgba(59, 130, 246, 0.25)', label: 'MEDIUM — Plan Fix' },
  low: { color: '#6b7280', bg: 'rgba(107, 114, 128, 0.08)', border: 'rgba(107, 114, 128, 0.2)', label: 'LOW — Monitor' },
};
