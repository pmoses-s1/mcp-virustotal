import { queryVirusTotal, queryVirusTotalWithRelationships } from '../utils/api.js';
import { formatIpResults, formatIpRelationshipItem, formatRelationshipPage, } from '../formatters/index.js';
import { logToFile } from '../utils/logging.js';
const DEFAULT_RELATIONSHIPS = [
    'communicating_files',
    'downloaded_files',
    'historical_ssl_certificates',
    'resolutions',
    'related_threat_actors',
    'urls',
];
export async function handleGetIpReport(args) {
    const { ip } = args;
    logToFile('Getting IP report with relationships...');
    const report = await queryVirusTotalWithRelationships(`/ip_addresses/${ip}`, DEFAULT_RELATIONSHIPS);
    return {
        content: [formatIpResults(report.data)],
    };
}
export async function handleGetIpRelationship(args) {
    const { ip, relationship, limit, cursor } = args;
    const params = { limit };
    if (cursor)
        params.cursor = cursor;
    const result = await queryVirusTotal(`/ip_addresses/${ip}/${relationship}`, 'get', undefined, params);
    return {
        content: [
            formatRelationshipPage({
                entity: 'ip',
                entityId: ip,
                relationship,
                data: result.data,
                meta: result.meta,
                renderItem: formatIpRelationshipItem,
            }),
        ],
    };
}
