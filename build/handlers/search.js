import { queryVirusTotal } from '../utils/api.js';
import { formatSearchResults } from '../formatters/index.js';
import { logToFile } from '../utils/logging.js';
export async function handleSearch(args) {
    const { query, limit, cursor } = args;
    const params = { query, limit };
    if (cursor)
        params.cursor = cursor;
    logToFile(`Searching VT corpus: ${query}`);
    const result = await queryVirusTotal('/search', 'get', undefined, params);
    return {
        content: [formatSearchResults(query, result.data, result.meta)],
    };
}
