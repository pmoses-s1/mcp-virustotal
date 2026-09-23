import { queryVirusTotal, queryVirusTotalWithRelationships } from '../utils/api.js';
import { formatFileResults, formatFileRelationshipItem, formatBehaviourSummary, formatRelationshipPage, } from '../formatters/index.js';
import { logToFile } from '../utils/logging.js';
const DEFAULT_RELATIONSHIPS = [
    'behaviours',
    'contacted_domains',
    'contacted_ips',
    'contacted_urls',
    'dropped_files',
    'execution_parents',
    'embedded_domains',
    'embedded_ips',
    'embedded_urls',
    'itw_domains',
    'itw_ips',
    'itw_urls',
    'related_threat_actors',
    'similar_files',
];
export async function handleGetFileReport(args) {
    const { hash } = args;
    logToFile('Getting file report with relationships...');
    const report = await queryVirusTotalWithRelationships(`/files/${hash}`, DEFAULT_RELATIONSHIPS);
    return {
        content: [formatFileResults(report.data)],
    };
}
export async function handleGetFileRelationship(args) {
    const { hash, relationship, limit, cursor } = args;
    const params = { limit };
    if (cursor)
        params.cursor = cursor;
    const result = await queryVirusTotal(`/files/${hash}/${relationship}`, 'get', undefined, params);
    return {
        content: [
            formatRelationshipPage({
                entity: 'file',
                entityId: hash,
                relationship,
                data: result.data,
                meta: result.meta,
                renderItem: formatFileRelationshipItem,
            }),
        ],
    };
}
export async function handleGetFileBehaviourSummary(args) {
    const { hash } = args;
    logToFile(`Getting behaviour summary for ${hash}`);
    const result = await queryVirusTotal(`/files/${hash}/behaviour_summary`);
    return {
        content: [formatBehaviourSummary(hash, result.data)],
    };
}
