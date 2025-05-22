# Web Security Scanner MCP Server

An MCP server that provides tools for scanning web applications for common security vulnerabilities.

## Features

- Scans for Cross-Site Scripting (XSS) vulnerabilities
- Detects potential Cross-Site Request Forgery (CSRF) issues
- Identifies potential Open Redirect vulnerabilities

## Installation

1. Clone this repository
2. Install dependencies:
```bash
npm install
```

## Building

```bash
npm run build
```

## Running

```bash
npm start
```

## Usage

The server provides the following MCP tool:

### scan-website

Scans a website for security vulnerabilities.

Parameters:
- `url`: The URL of the website to scan (must be a valid URL)
- `scanTypes`: Array of scan types to perform. Must include at least one of:
  - `xss`: Cross-Site Scripting scan
  - `csrf`: Cross-Site Request Forgery scan
  - `openredirect`: Open Redirect vulnerability scan

Example usage with MCP client:

```typescript
const result = await client.callTool({
  name: "scan-website",
  arguments: {
    url: "https://example.com",
    scanTypes: ["xss", "csrf", "openredirect"]
  }
});
```

## Development

To run in development mode with automatic reloading:

```bash
npm run dev
```

## License

MIT 