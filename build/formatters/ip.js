// src/formatters/ip.ts
import { formatDateTime, formatDetectionResults } from './utils.js';
import { logToFile } from '../utils/logging.js';
export function formatRelationshipData(relType, item) {
    const attrs = item.attributes || {};
    switch (relType) {
        case 'communicating_files':
        case 'downloaded_files':
            return `  • ${attrs.meaningful_name || item.id}
    Type: ${attrs.type_description || attrs.type || 'Unknown'}
    First Seen: ${attrs.first_submission_date ? formatDateTime(attrs.first_submission_date) : 'Unknown'}`;
        case 'historical_ssl_certificates':
            const certInfo = [];
            if (attrs.subject?.CN)
                certInfo.push(`Subject: ${attrs.subject.CN}`);
            if (attrs.issuer?.CN)
                certInfo.push(`Issuer: ${attrs.issuer.CN}`);
            if (attrs.validity?.not_before)
                certInfo.push(`Valid From: ${formatDateTime(new Date(attrs.validity.not_before).getTime() / 1000)}`);
            if (attrs.validity?.not_after)
                certInfo.push(`Valid Until: ${formatDateTime(new Date(attrs.validity.not_after).getTime() / 1000)}`);
            if (attrs.serial_number)
                certInfo.push(`Serial: ${attrs.serial_number}`);
            return `  • SSL Certificate${certInfo.length ? '\n    ' + certInfo.join('\n    ') : ''}`;
        case 'resolutions':
            return `  • Host: ${attrs.host_name || 'Unknown'}
    Last Resolved: ${attrs.date ? formatDateTime(Number(attrs.date)) : 'Unknown'}`;
        case 'related_threat_actors':
            return `  • ${attrs.name || item.id}
    Description: ${attrs.description || 'No description available'}`;
        case 'urls':
            return `  • ${attrs.url || item.id}
    Last Analysis: ${attrs.last_analysis_date ? formatDateTime(attrs.last_analysis_date) : 'Unknown'}
    Reputation: ${attrs.reputation ?? 'Unknown'}`;
        default:
            return `  • ${item.id}`;
    }
}
export function formatIpResults(data) {
    try {
        const attributes = data?.attributes || {};
        const stats = attributes?.last_analysis_stats || {};
        const votes = attributes?.total_votes || { harmless: 0, malicious: 0 };
        const tags = attributes?.tags || [];
        let outputArray = [
            `🌐 IP Address Analysis`,
            `IP: ${data?.id || data?.ip || 'Unknown IP'}`,
            ``,
            `📍 Network Information:`,
            `• AS Owner: ${attributes?.as_owner || 'Unknown'}`,
            attributes?.asn ? `• ASN: ${attributes.asn}` : null,
            `• Network: ${attributes?.network || 'Unknown'}`,
            `• Country: ${attributes?.country || 'Unknown'}`,
            `• Continent: ${attributes?.continent || 'Unknown'}`,
            `• Registry: ${attributes?.regional_internet_registry || 'Unknown'}`,
            ``,
            `📊 Analysis Statistics:`,
            formatDetectionResults(stats),
        ].filter(Boolean);
        // Add reputation and votes
        const reputation = attributes?.reputation ?? 'N/A';
        outputArray.push(``, `👥 Community Feedback:`, `• Reputation Score: ${reputation}`, `• Harmless Votes: ${votes.harmless}`, `• Malicious Votes: ${votes.malicious}`);
        // Add JARM hash if available
        if (attributes?.jarm) {
            outputArray.push(``, `🔒 JARM Hash:`, attributes.jarm);
        }
        // Add HTTPS certificate information if available
        if (attributes?.last_https_certificate) {
            const cert = attributes.last_https_certificate;
            outputArray.push(``, `📜 SSL Certificate:`, `• Subject: ${cert.subject?.CN || 'Unknown'}`, `• Issuer: ${[cert.issuer?.O, cert.issuer?.CN].filter(Boolean).join(' - ')}`, `• Valid From: ${formatDateTime(new Date(cert.validity.not_before).getTime() / 1000)}`, `• Valid Until: ${formatDateTime(new Date(cert.validity.not_after).getTime() / 1000)}`, `• Serial Number: ${cert.serial_number}`, `• Version: ${cert.version}`, `• SHA-256 Fingerprint: ${cert.thumbprint_sha256}`);
            // Add certificate extensions if available
            if (cert.extensions) {
                if (cert.extensions.subject_alternative_name?.length) {
                    outputArray.push(`• Alternative Names:`, ...cert.extensions.subject_alternative_name.map((name) => `  - ${name}`));
                }
                if (cert.extensions.certificate_policies?.length) {
                    outputArray.push(`• Certificate Policies:`, ...cert.extensions.certificate_policies.map((policy) => `  - ${policy}`));
                }
                if (cert.extensions.extended_key_usage?.length) {
                    outputArray.push(`• Extended Key Usage:`, ...cert.extensions.extended_key_usage.map((usage) => `  - ${usage}`));
                }
            }
        }
        // Add tags if available
        if (tags.length > 0) {
            outputArray.push(``, `🏷️ Tags:`, ...tags.map((tag) => `• ${tag}`));
        }
        // Add key WHOIS information if available
        if (attributes?.whois) {
            const whoisLines = attributes.whois.split('\n');
            const keyFields = [
                'Organization:',
                'OrgName:',
                'Country:',
                'City:',
                'Address:',
                'RegDate:',
                'NetName:',
                'NetType:',
                'Comment:'
            ];
            const relevantWhois = whoisLines
                .filter((line) => keyFields.some(field => line.trim().startsWith(field)))
                .filter((item, index, self) => self.indexOf(item) === index); // Remove duplicates
            if (relevantWhois.length > 0) {
                outputArray.push(``, `📋 WHOIS Information:`, ...relevantWhois.map((line) => `• ${line.trim()}`), attributes.whois_date ?
                    `\nLast Updated: ${formatDateTime(attributes.whois_date)}` : null);
            }
        }
        // Format relationships if available
        if (data.relationships) {
            outputArray.push('\n🔗 Relationships:');
            for (const [relType, relData] of Object.entries(data.relationships)) {
                const count = relData.meta?.count || (Array.isArray(relData.data) ? relData.data.length : 1);
                outputArray.push(`\n${relType} (${count} items):`);
                if (Array.isArray(relData.data)) {
                    relData.data.forEach(item => {
                        outputArray.push(formatRelationshipData(relType, item));
                    });
                }
                else if (relData.data) {
                    outputArray.push(formatRelationshipData(relType, relData.data));
                }
            }
        }
        return {
            type: "text",
            text: outputArray.filter(Boolean).join('\n')
        };
    }
    catch (error) {
        logToFile(`Error formatting IP results: ${error}`);
        return {
            type: "text",
            text: "Error formatting IP results"
        };
    }
}
