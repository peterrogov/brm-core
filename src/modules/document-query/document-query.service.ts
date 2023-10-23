import { Injectable } from '@nestjs/common';
import jmespath from 'jmespath';
import jsonpath from 'jsonpath';
import { JsonQueryType } from './document-query.types';

/**
 * Provides utility methods for symmetric encryption and decryption operations.
 * This includes methods for encrypting/decrypting Buffers, handling encrypted
 * envelopes (which bundle together encrypted data and their associated IVs and
 * cipher types), encoding/decoding envelopes to/from strings, secure hashing, 
 * and key/IV generation.
 */
@Injectable()
export class DocumentQueryService {
    /**
     * Detects the type of the given query.
     * Note: This function is simple and uses heuristics; there are cases where
     * it might not be 100% accurate.
     * @param query - The query string.
     * @returns - JsonQueryType.
     */
    private detectQueryType(query: string): JsonQueryType {
        if (query.startsWith('$')) {
            return JsonQueryType.JSONPath;
        }
        // Add more conditions if needed
        return JsonQueryType.JMESPath;
    }

    /**
     * Check if a given object matches a JSONPath query.
     * @param doc - The object to query against.
     * @param query - The JSONPath query string.
     * @returns - True if the object matches the query, otherwise false.
     */
    private matchesJsonPath(doc: Object, query: string): boolean {
        try {
            const result = jsonpath.query([doc], query);
            return result.length > 0;
        } catch (error) {
            throw new Error("Error evaluating JSONPath query:" + error);
        }
    }

    /**
     * Check if a given object matches a JMESPath query.
     * @param doc - The object to query against.
     * @param query - The JMESPath query string.
     * @returns - True if the object matches the query, otherwise false.
     */
    private matchesJmesPath(doc: Object, query: string): boolean {
        try {
            const result = jmespath.search(doc, query);
            return Boolean(result);
        } catch (error) {
            throw new Error("Error evaluating JMESPath query:" + error);
        }
    }

    /**
     * Checks if a given object matches a query, determining the query type automatically.
     * @param doc - The object to query against.
     * @param query - The query string, either JSONPath or JMESPath.
     * @returns - True if the object matches the query, otherwise false.
     */
    matchesQuery(doc: Object, query: string): boolean {
        if (typeof doc !== "object") {
            throw new Error("Object expected");
        }

        switch (this.detectQueryType(query)) {
            case JsonQueryType.JSONPath:
                return this.matchesJsonPath(doc, query);
            case JsonQueryType.JMESPath:
                return this.matchesJmesPath(doc, query);
            default:
                throw new Error("Unrecognized or invalid query");
        }
    }
}