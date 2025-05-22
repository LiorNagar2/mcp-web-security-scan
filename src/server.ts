import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { performScan, ScanOptions } from "./scanners/index.js";

// Create an MCP server
const server = new McpServer({
    name: "Web Security Scanner",
    version: "1.0.0"
});

// Add a tool for scanning websites
server.tool(
    "scan-website",
    {
        url: z.string().url(),
        scanTypes: z.array(z.enum([
            'xss',
            'csrf',
            'openredirect',
            'sensitive',
            'sqlinjection',
            'headers',
            'infodisclosure',
            'traversal'
        ])).min(1)
    },
    async ({ url, scanTypes }: {
        url: string;
        scanTypes: (
            'xss' |
            'csrf' |
            'openredirect' |
            'sensitive' |
            'sqlinjection' |
            'headers' |
            'infodisclosure' |
            'traversal'
        )[]
    }) => {
        try {
            const options: ScanOptions = {
                url,
                scanTypes
            };

            const results = await performScan(options);

            // Format results for display
            const formattedResults = results.map(result => {
                let text = `[${result.severity.toUpperCase()}] ${result.vulnerability}\n`;
                text += `Description: ${result.description}\n`;
                if (result.location) {
                    text += `Location: ${result.location}\n`;
                }
                if (result.evidence) {
                    text += `Evidence: ${result.evidence}\n`;
                }
                return text;
            }).join('\n---\n\n');

            return {
                content: [{
                    type: "text",
                    text: formattedResults || "No vulnerabilities found."
                }]
            };
        } catch (error) {
            return {
                content: [{
                    type: "text",
                    text: `Error performing scan: ${error instanceof Error ? error.message : 'Unknown error'}`
                }],
                isError: true
            };
        }
    }
);

// Add a prompt for scanning websites
server.prompt(
    "scan-website",
    "Scan a website for security vulnerabilities",
    async (extra) => ({
        messages: [{
            role: "user",
            content: {
                type: "text",
                text: "Please provide a URL and specify which security scans to perform (xss, csrf, openredirect, sensitive, sqlinjection, headers, infodisclosure, traversal)"
            }
        }]
    })
);

// Start the server with stdio transport
const transport = new StdioServerTransport();
await server.connect(transport);

console.error('Web Security Scanner MCP server is running...'); 