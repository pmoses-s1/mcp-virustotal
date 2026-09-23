// src/formatters/domain.ts
import { formatDateTime, formatDetectionResults } from './utils.js';
import { logToFile } from '../utils/logging.js';
export function formatDomainResults(data) {
    try {
        const attributes = data?.attributes || {};
        const stats = attributes?.last_analysis_stats || {};
        const categories = attributes?.categories || {};
        const ranks = attributes?.popularity_ranks || {};
        const whois = attributes?.whois || '';
        const dnsRecords = attributes?.last_dns_records || [];
        const threatSeverity = attributes?.threat_severity;
        const votes = attributes?.total_votes;
        let outputArray = [
            `🌍 Domain Analysis Results`,
            `Domain: ${data?.id || 'Unknown Domain'}`,
            `📅 Last Analysis Date: ${attributes.last_analysis_date ? formatDateTime(attributes.last_analysis_date) : 'N/A'}`,
            `📊 Reputation Score: ${attributes?.reputation ?? 'N/A'}`,
            "",
            "Analysis Statistics:",
            formatDetectionResults(stats),
        ];
        // Add threat severity if available
        if (threatSeverity && threatSeverity.threat_severity_level) {
            const severityData = threatSeverity.threat_severity_data;
            outputArray.push("", "Threat Severity:", `Level: ${threatSeverity.threat_severity_level}`, `Description: ${threatSeverity.level_description || 'N/A'}`, ...(severityData ? [
                `Detections: ${severityData.num_detections}`,
                `Bad Collection: ${severityData.belongs_to_bad_collection ? 'Yes' : 'No'}`
            ] : []));
        }
        // Add categories if available
        if (Object.keys(categories).length > 0) {
            outputArray = [
                ...outputArray,
                "",
                "Categories:",
                ...Object.entries(categories).map(([service, category]) => `• ${service}: ${category}`)
            ];
        }
        // Add DNS records if available
        if (dnsRecords.length > 0) {
            outputArray = [
                ...outputArray,
                "",
                "Latest DNS Records:",
                ...dnsRecords.map((record) => `• ${record.type}: ${record.value} (TTL: ${record.ttl})`)
            ];
        }
        // Add popularity rankings if available
        if (Object.keys(ranks).length > 0) {
            outputArray = [
                ...outputArray,
                "",
                "Popularity Rankings:",
                ...Object.entries(ranks).map(([service, data]) => `• ${service}: Rank ${data.rank || 'N/A'}`)
            ];
        }
        // Add key WHOIS information
        if (whois) {
            const whoisLines = whois.split('\n');
            const keyFields = [
                'Registrar:',
                'Creation Date:',
                'Registry Expiry Date:',
                'Updated Date:',
                'Registrant Organization:',
                'Admin Organization:'
            ];
            const relevantWhois = whoisLines
                .filter((line) => keyFields.some(field => line.startsWith(field)))
                .filter((item, index, self) => self.indexOf(item) === index); // Remove duplicates
            if (relevantWhois.length > 0) {
                outputArray = [
                    ...outputArray,
                    "",
                    "WHOIS Information:",
                    ...relevantWhois.map((line) => `• ${line.trim()}`)
                ];
            }
        }
        // Add creation and modification dates
        if (attributes.creation_date) {
            outputArray.push(`\nCreation Date: ${formatDateTime(attributes.creation_date)}`);
        }
        if (attributes.last_modification_date) {
            outputArray.push(`Last Modified: ${formatDateTime(attributes.last_modification_date)}`);
        }
        // Add total votes if available
        if (votes) {
            outputArray.push("", "Community Votes:", `• Harmless: ${votes.harmless || 0}`, `• Malicious: ${votes.malicious || 0}`);
        }
        // Format relationships if available
        if (data.relationships) {
            outputArray.push('\n🔗 Relationships:');
            for (const [relType, relData] of Object.entries(data.relationships)) {
                const typedRelData = relData;
                const count = typedRelData.meta?.count ||
                    (Array.isArray(typedRelData.data) ? typedRelData.data.length : 1);
                outputArray.push(`\n${relType} (${count} items):`);
                if (Array.isArray(typedRelData.data)) {
                    typedRelData.data.forEach(item => {
                        if (item.formattedOutput) {
                            outputArray.push(item.formattedOutput);
                        }
                    });
                }
                else if (typedRelData.data && 'formattedOutput' in typedRelData.data && typedRelData.data.formattedOutput) {
                    outputArray.push(typedRelData.data.formattedOutput);
                }
            }
        }
        return {
            type: "text",
            text: outputArray.join('\n')
        };
    }
    catch (error) {
        logToFile(`Error formatting domain results: ${error}`);
        return {
            type: "text",
            text: "Error formatting domain results"
        };
    }
}
