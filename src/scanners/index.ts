import axios from 'axios';
import * as cheerio from 'cheerio';

interface ScanResult {
    vulnerability: string;
    description: string;
    severity: 'low' | 'medium' | 'high';
    location?: string;
    evidence?: string;
}

export async function scanXSS(url: string): Promise<ScanResult[]> {
    const results: ScanResult[] = [];
    try {
        const response = await axios.get(url);
        const $ = cheerio.load(response.data);

        // Check for reflected input parameters
        const urlParams = new URL(url).searchParams;
        for (const [param, value] of urlParams.entries()) {
            if (response.data.includes(value)) {
                results.push({
                    vulnerability: 'Potential Reflected XSS',
                    description: `URL parameter "${param}" is reflected in the response without proper encoding`,
                    severity: 'high',
                    location: `Parameter: ${param}`,
                    evidence: `Value "${value}" found in response`
                });
            }
        }

        // Check for unsafe DOM practices
        $('script').each((_, elem) => {
            const content = $(elem).html() || '';
            if (content.includes('innerHTML') || content.includes('document.write')) {
                results.push({
                    vulnerability: 'Potential DOM-based XSS',
                    description: 'Unsafe JavaScript DOM manipulation detected',
                    severity: 'medium',
                    evidence: content.substring(0, 100) + '...'
                });
            }
        });

    } catch (error) {
        results.push({
            vulnerability: 'Scan Error',
            description: `Failed to scan for XSS: ${error instanceof Error ? error.message : 'Unknown error'}`,
            severity: 'low'
        });
    }

    return results;
}

export async function scanCSRF(url: string): Promise<ScanResult[]> {
    const results: ScanResult[] = [];
    try {
        const response = await axios.get(url);
        const $ = cheerio.load(response.data);

        // Check for CSRF tokens in forms
        $('form').each((_, form) => {
            const hasCSRFToken = $(form).find('input[name*=csrf], input[name*=token]').length > 0;
            if (!hasCSRFToken) {
                results.push({
                    vulnerability: 'Missing CSRF Protection',
                    description: 'Form found without CSRF token',
                    severity: 'high',
                    location: $(form).attr('action') || url,
                    evidence: $(form).toString().substring(0, 100) + '...'
                });
            }
        });

        // Check for secure headers
        const headers = response.headers;
        if (!headers['x-csrf-token'] && !headers['csrf-token']) {
            results.push({
                vulnerability: 'Missing CSRF Headers',
                description: 'No CSRF protection headers detected',
                severity: 'medium',
                evidence: 'Headers: ' + JSON.stringify(headers)
            });
        }

    } catch (error) {
        results.push({
            vulnerability: 'Scan Error',
            description: `Failed to scan for CSRF: ${error instanceof Error ? error.message : 'Unknown error'}`,
            severity: 'low'
        });
    }

    return results;
}

export async function scanOpenRedirects(url: string): Promise<ScanResult[]> {
    const results: ScanResult[] = [];
    try {
        const response = await axios.get(url);
        const $ = cheerio.load(response.data);

        // Check for potentially unsafe redirects in links
        $('a[href]').each((_, elem) => {
            const href = $(elem).attr('href');
            if (href && (
                href.includes('redirect=') ||
                href.includes('return=') ||
                href.includes('next=') ||
                href.includes('url=')
            )) {
                results.push({
                    vulnerability: 'Potential Open Redirect',
                    description: 'Link contains redirect parameter that might be manipulated',
                    severity: 'medium',
                    location: href,
                    evidence: $(elem).toString()
                });
            }
        });

        // Check for JavaScript-based redirects
        $('script').each((_, elem) => {
            const content = $(elem).html() || '';
            if (
                content.includes('window.location') ||
                content.includes('location.href') ||
                content.includes('location.replace')
            ) {
                results.push({
                    vulnerability: 'Potential JavaScript Redirect',
                    description: 'JavaScript code contains redirect functionality that might be manipulated',
                    severity: 'medium',
                    evidence: content.substring(0, 100) + '...'
                });
            }
        });

    } catch (error) {
        results.push({
            vulnerability: 'Scan Error',
            description: `Failed to scan for open redirects: ${error instanceof Error ? error.message : 'Unknown error'}`,
            severity: 'low'
        });
    }

    return results;
}

export async function scanSensitiveData(url: string): Promise<ScanResult[]> {
    const results: ScanResult[] = [];
    const TIMEOUT = 5000; // 5 second timeout for each request
    const MAX_CONCURRENT_REQUESTS = 3; // Limit concurrent requests

    try {
        const response = await axios.get(url, { timeout: TIMEOUT });
        const $ = cheerio.load(response.data);
        const htmlContent = response.data;
        const baseUrl = new URL(url).origin;

        // Common patterns for sensitive data
        const patterns = {
            apiKey: /(['"]?(?:api[_-]?key|api[_-]?token)['"]?\s*[:=]\s*['"]([a-zA-Z0-9_\-]{20,})['"])/i,
            awsKey: /AKIA[0-9A-Z]{16}/,
            privateKey: /-----BEGIN [A-Z]+ PRIVATE KEY-----/,
            password: /(['"]?(?:password|passwd|pwd)['"]?\s*[:=]\s*['"]([^'"]{8,})['"])/i,
            jwt: /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/,
            email: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
            creditCard: /\b(?:\d[ -]*?){13,16}\b/,
            secretKey: /(['"]?secret[_-]?key['"]?\s*[:=]\s*['"]([^'"]{8,})['"])/i
        };

        // High-priority sensitive file patterns
        const sensitiveFilePatterns = [
            '.env',
            'config.json',
            'credentials.json',
            'database.json',
            'secrets.json',
            'auth.json'
        ];

        // Check content for sensitive patterns
        for (const [type, pattern] of Object.entries(patterns)) {
            const matches = htmlContent.match(pattern);
            if (matches) {
                results.push({
                    vulnerability: 'Exposed Sensitive Data',
                    description: `Found ${type} pattern in page content`,
                    severity: 'high',
                    location: url,
                    evidence: `Found ${matches.length} matches of ${type} pattern`
                });
            }
        }

        // Check HTML comments for sensitive data
        const comments = $('*').contents().filter(function () {
            return this.type === 'comment';
        });

        comments.each((_, comment) => {
            const commentText = (comment as any).data as string;
            for (const [type, pattern] of Object.entries(patterns)) {
                if (pattern.test(commentText)) {
                    results.push({
                        vulnerability: 'Sensitive Data in Comments',
                        description: `Found ${type} pattern in HTML comment`,
                        severity: 'high',
                        location: url,
                        evidence: 'Found sensitive data pattern in HTML comment (redacted for security)'
                    });
                }
            }
        });

        // Function to check a single file with timeout
        async function checkFile(filePath: string): Promise<void> {
            try {
                const fileUrl = new URL(filePath, baseUrl).toString();
                const fileResponse = await axios.get(fileUrl, {
                    timeout: TIMEOUT,
                    validateStatus: (status) => status < 500 // Accept any status < 500 to avoid errors
                });

                if (fileResponse.status === 200) {
                    const fileContent = fileResponse.data;
                    const fileContentStr = typeof fileContent === 'string'
                        ? fileContent
                        : JSON.stringify(fileContent);

                    for (const [type, pattern] of Object.entries(patterns)) {
                        if (pattern.test(fileContentStr)) {
                            results.push({
                                vulnerability: 'Exposed Sensitive File',
                                description: `Found ${type} pattern in exposed file`,
                                severity: 'high',
                                location: fileUrl,
                                evidence: `File ${filePath} contains sensitive data pattern`
                            });
                            break; // One finding per file is enough
                        }
                    }
                }
            } catch (error) {
                // Ignore 404s and timeouts
                if (axios.isAxiosError(error) && error.response?.status !== 404 && error.code !== 'ECONNABORTED') {
                    results.push({
                        vulnerability: 'File Access Error',
                        description: `Error accessing potential sensitive file: ${error.message}`,
                        severity: 'low',
                        location: filePath
                    });
                }
            }
        }

        // Process files in batches to limit concurrent requests
        const processFiles = async (files: string[]) => {
            for (let i = 0; i < files.length; i += MAX_CONCURRENT_REQUESTS) {
                const batch = files.slice(i, i + MAX_CONCURRENT_REQUESTS);
                await Promise.all(batch.map(file => checkFile(file)));
            }
        };

        // Check high-priority sensitive files first
        await processFiles(sensitiveFilePatterns);

        // Check for additional sensitive files in links, but limit the scope
        const fileLinks = new Set<string>();
        $('a[href]').each((_, elem) => {
            const href = $(elem).attr('href');
            if (href && /\.(json|xml|yaml|yml|env|config|log)$/i.test(href)) {
                fileLinks.add(href);
            }
        });

        // Only check the first 10 discovered files to prevent timeout
        const discoveredFiles = Array.from(fileLinks).slice(0, 10);
        await processFiles(discoveredFiles);

    } catch (error) {
        results.push({
            vulnerability: 'Scan Error',
            description: `Failed to scan for sensitive data: ${error instanceof Error ? error.message : 'Unknown error'}`,
            severity: 'low'
        });
    }

    return results;
}

export async function scanSQLInjection(url: string): Promise<ScanResult[]> {
    const results: ScanResult[] = [];
    const TIMEOUT = 3000; // 3 second timeout for each request
    const MAX_CONCURRENT_REQUESTS = 2; // Limit concurrent requests

    // Safe SQL injection test payloads that won't harm the database
    const testPayloads = [
        `' OR '1'='1`,
        `" OR "1"="1`,
        `' OR 1=1--`,
        `admin' --`,
        `1' ORDER BY 1--`
    ];

    // SQL error patterns to detect in responses
    const sqlErrorPatterns = [
        /SQL syntax.*?MySQL/i,
        /Warning.*?\Wmysqli?_/i,
        /PostgreSQL.*?ERROR/i,
        /Driver.*? SQL[\-\_\ ]*Server/i,
        /ORA-[0-9][0-9][0-9][0-9]/i,
        /SQLITE_ERROR/i,
        /System\.Data\.SqlClient\.SqlException/i,
        /Unclosed quotation mark after the character string/i
    ];

    try {
        const response = await axios.get(url, {
            timeout: TIMEOUT,
            validateStatus: (status) => status < 500 // Accept any status < 500
        });
        const $ = cheerio.load(response.data);
        const baseResponse = response.data;
        const baseResponseLength = baseResponse.length;

        // Function to test a single input with a payload
        async function testInput(formAction: string, method: string, inputName: string, payload: string, allInputs: any): Promise<void> {
            try {
                const formData = new URLSearchParams();
                allInputs.each(function (this: any, index: number, input: any) {
                    const $input = $(input);
                    const name = $input.attr('name') || '';
                    formData.append(name, name === inputName ? payload : ($input.attr('value') || ''));
                });

                const requestConfig = {
                    timeout: TIMEOUT,
                    validateStatus: (status: number) => status < 500
                };

                let testResponse;
                if (method === 'GET') {
                    const testUrl = new URL(formAction);
                    formData.forEach((value, key) => testUrl.searchParams.append(key, value));
                    testResponse = await axios.get(testUrl.toString(), requestConfig);
                } else {
                    testResponse = await axios.post(formAction, formData, requestConfig);
                }

                const responseText = testResponse.data?.toString() || '';

                // Check for SQL errors
                for (const pattern of sqlErrorPatterns) {
                    if (pattern.test(responseText) && !pattern.test(baseResponse)) {
                        results.push({
                            vulnerability: 'SQL Injection Detected',
                            description: `Form input "${inputName}" is vulnerable to SQL injection`,
                            severity: 'high',
                            location: `Form: ${formAction}, Input: ${inputName}`,
                            evidence: `Payload "${payload}" triggered SQL error pattern: ${pattern}`
                        });
                        return; // Stop testing this input if vulnerability found
                    }
                }

                // Check for significant response differences
                const responseDiff = Math.abs(testResponse.data?.length - baseResponseLength);
                if (
                    testResponse.status !== response.status ||
                    responseDiff > baseResponseLength * 0.3
                ) {
                    results.push({
                        vulnerability: 'Potential SQL Injection',
                        description: `Form input "${inputName}" shows unusual behavior with SQL injection payload`,
                        severity: 'medium',
                        location: `Form: ${formAction}, Input: ${inputName}`,
                        evidence: `Payload "${payload}" caused significant response difference. Status: ${testResponse.status}, Size diff: ${responseDiff} bytes`
                    });
                }
            } catch (error) {
                // Ignore timeouts and connection errors
                if (axios.isAxiosError(error) && error.code !== 'ECONNABORTED' && error.code !== 'ECONNREFUSED') {
                    results.push({
                        vulnerability: 'Potential SQL Injection',
                        description: `Form input "${inputName}" caused an error with SQL injection payload`,
                        severity: 'medium',
                        location: `Form: ${formAction}, Input: ${inputName}`,
                        evidence: `Payload "${payload}" caused error: ${error.message}`
                    });
                }
            }
        }

        // Process forms
        const forms = $('form').toArray();
        for (const form of forms) {
            const $form = $(form);
            const formAction = $form.attr('action') || url;
            const method = ($form.attr('method') || 'GET').toUpperCase();
            const inputs = $form.find('input[type="text"], input[type="search"], input:not([type]), input[type="password"]');

            // Process inputs in batches
            for (const input of inputs.toArray()) {
                const $input = $(input);
                const inputName = $input.attr('name') || '';

                // Process payloads in batches
                for (let i = 0; i < testPayloads.length; i += MAX_CONCURRENT_REQUESTS) {
                    const payloadBatch = testPayloads.slice(i, i + MAX_CONCURRENT_REQUESTS);
                    await Promise.all(
                        payloadBatch.map(payload =>
                            testInput(formAction, method, inputName, payload, inputs)
                        )
                    );
                }
            }
        }

        // Test URL parameters
        const urlParams = new URL(url).searchParams;
        const paramEntries = Array.from(urlParams.entries());

        // Process URL parameters in batches
        for (const [param] of paramEntries) {
            for (let i = 0; i < testPayloads.length; i += MAX_CONCURRENT_REQUESTS) {
                const payloadBatch = testPayloads.slice(i, i + MAX_CONCURRENT_REQUESTS);
                await Promise.all(
                    payloadBatch.map(async (payload) => {
                        try {
                            const testUrl = new URL(url);
                            urlParams.forEach((v, k) => {
                                testUrl.searchParams.set(k, k === param ? payload : v);
                            });

                            const testResponse = await axios.get(testUrl.toString(), {
                                timeout: TIMEOUT,
                                validateStatus: (status) => status < 500
                            });

                            const responseText = testResponse.data?.toString() || '';

                            // Check for SQL errors
                            for (const pattern of sqlErrorPatterns) {
                                if (pattern.test(responseText) && !pattern.test(baseResponse)) {
                                    results.push({
                                        vulnerability: 'SQL Injection Detected',
                                        description: `URL parameter "${param}" is vulnerable to SQL injection`,
                                        severity: 'high',
                                        location: url,
                                        evidence: `Payload "${payload}" triggered SQL error pattern: ${pattern}`
                                    });
                                    return;
                                }
                            }

                            // Check for significant response differences
                            const responseDiff = Math.abs(testResponse.data?.length - baseResponseLength);
                            if (
                                testResponse.status !== response.status ||
                                responseDiff > baseResponseLength * 0.3
                            ) {
                                results.push({
                                    vulnerability: 'Potential SQL Injection',
                                    description: `URL parameter "${param}" shows unusual behavior with SQL injection payload`,
                                    severity: 'medium',
                                    location: url,
                                    evidence: `Payload "${payload}" caused significant response difference. Status: ${testResponse.status}, Size diff: ${responseDiff} bytes`
                                });
                            }
                        } catch (error) {
                            // Ignore timeouts and connection errors
                            if (axios.isAxiosError(error) && error.code !== 'ECONNABORTED' && error.code !== 'ECONNREFUSED') {
                                results.push({
                                    vulnerability: 'Potential SQL Injection',
                                    description: `URL parameter "${param}" caused an error with SQL injection payload`,
                                    severity: 'medium',
                                    location: url,
                                    evidence: `Payload "${payload}" caused error: ${error.message}`
                                });
                            }
                        }
                    })
                );
            }
        }

    } catch (error) {
        results.push({
            vulnerability: 'Scan Error',
            description: `Failed to scan for SQL injection: ${error instanceof Error ? error.message : 'Unknown error'}`,
            severity: 'low'
        });
    }

    return results;
}

export async function scanInsecureHeaders(url: string): Promise<ScanResult[]> {
    const results: ScanResult[] = [];
    try {
        const response = await axios.get(url);
        const headers = response.headers;

        // Security Headers to check
        const securityHeaders = {
            'strict-transport-security': 'Missing HSTS header',
            'x-content-type-options': 'Missing X-Content-Type-Options header',
            'x-frame-options': 'Missing X-Frame-Options header',
            'content-security-policy': 'Missing Content Security Policy',
            'x-xss-protection': 'Missing X-XSS-Protection header',
            'referrer-policy': 'Missing Referrer Policy',
            'permissions-policy': 'Missing Permissions Policy'
        };

        // Check for missing security headers
        for (const [header, message] of Object.entries(securityHeaders)) {
            if (!headers[header]) {
                results.push({
                    vulnerability: 'Missing Security Header',
                    description: message,
                    severity: 'medium',
                    evidence: `Header "${header}" not found in response`
                });
            }
        }

        // Check for insecure cookie settings
        const cookies = headers['set-cookie'] || [];
        cookies.forEach((cookie: string) => {
            if (!cookie.includes('Secure') || !cookie.includes('HttpOnly')) {
                results.push({
                    vulnerability: 'Insecure Cookie Configuration',
                    description: 'Cookie missing Secure and/or HttpOnly flags',
                    severity: 'medium',
                    evidence: cookie
                });
            }
        });

    } catch (error) {
        results.push({
            vulnerability: 'Scan Error',
            description: `Failed to scan security headers: ${error instanceof Error ? error.message : 'Unknown error'}`,
            severity: 'low'
        });
    }

    return results;
}

export async function scanInformationDisclosure(url: string): Promise<ScanResult[]> {
    const results: ScanResult[] = [];
    try {
        const response = await axios.get(url);
        const $ = cheerio.load(response.data);
        const headers = response.headers;

        // Check for server information in headers
        const sensitiveHeaders = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version'];
        sensitiveHeaders.forEach(header => {
            if (headers[header]) {
                results.push({
                    vulnerability: 'Server Information Disclosure',
                    description: `Server revealing technology information through ${header} header`,
                    severity: 'medium',
                    evidence: `${header}: ${headers[header]}`
                });
            }
        });

        // Check for HTML comments containing sensitive information
        const comments = $('*').contents().filter(function () {
            return this.type === 'comment';
        });

        comments.each((_, comment) => {
            const commentText = (comment as any).data as string;
            if (
                commentText.toLowerCase().includes('todo') ||
                commentText.toLowerCase().includes('fixme') ||
                commentText.toLowerCase().includes('bug') ||
                commentText.toLowerCase().includes('debug')
            ) {
                results.push({
                    vulnerability: 'Information Disclosure in Comments',
                    description: 'HTML comments contain potentially sensitive development information',
                    severity: 'low',
                    evidence: commentText.substring(0, 100) + '...'
                });
            }
        });

        // Check for error messages
        if (response.data.includes('error in your SQL syntax') ||
            response.data.includes('SQLSTATE[') ||
            response.data.includes('ORA-') ||
            response.data.includes('Fatal error') ||
            response.data.includes('Warning:') ||
            response.data.includes('stack trace')) {
            results.push({
                vulnerability: 'Error Message Disclosure',
                description: 'Application is revealing detailed error messages',
                severity: 'medium',
                evidence: 'Found error message patterns in response'
            });
        }

    } catch (error) {
        results.push({
            vulnerability: 'Scan Error',
            description: `Failed to scan for information disclosure: ${error instanceof Error ? error.message : 'Unknown error'}`,
            severity: 'low'
        });
    }

    return results;
}

export async function scanDirectoryTraversal(url: string): Promise<ScanResult[]> {
    const results: ScanResult[] = [];
    try {
        const response = await axios.get(url);
        const $ = cheerio.load(response.data);

        // Check for file paths in URLs
        $('a[href]').each((_, elem) => {
            const href = $(elem).attr('href');
            if (href && (
                href.includes('../') ||
                href.includes('..\\') ||
                href.includes('file:') ||
                /\/(?:etc|usr|var|windows|system32)/i.test(href)
            )) {
                results.push({
                    vulnerability: 'Potential Directory Traversal',
                    description: 'Link contains suspicious path patterns',
                    severity: 'high',
                    location: href,
                    evidence: $(elem).toString()
                });
            }
        });

        // Check for file paths in parameters
        const urlParams = new URL(url).searchParams;
        for (const [param, value] of urlParams.entries()) {
            if (
                value.includes('../') ||
                value.includes('..\\') ||
                value.includes('file:') ||
                /\/(?:etc|usr|var|windows|system32)/i.test(value)
            ) {
                results.push({
                    vulnerability: 'Potential Directory Traversal',
                    description: `URL parameter "${param}" contains suspicious path patterns`,
                    severity: 'high',
                    location: url,
                    evidence: `Parameter ${param}=${value}`
                });
            }
        }

    } catch (error) {
        results.push({
            vulnerability: 'Scan Error',
            description: `Failed to scan for directory traversal: ${error instanceof Error ? error.message : 'Unknown error'}`,
            severity: 'low'
        });
    }

    return results;
}

export interface ScanOptions {
    url: string;
    scanTypes: ('xss' | 'csrf' | 'openredirect' | 'sensitive' | 'sqlinjection' | 'headers' | 'infodisclosure' | 'traversal')[];
}

export async function performScan(options: ScanOptions): Promise<ScanResult[]> {
    const results: ScanResult[] = [];

    for (const scanType of options.scanTypes) {
        switch (scanType) {
            case 'xss':
                results.push(...await scanXSS(options.url));
                break;
            case 'csrf':
                results.push(...await scanCSRF(options.url));
                break;
            case 'openredirect':
                results.push(...await scanOpenRedirects(options.url));
                break;
            case 'sensitive':
                results.push(...await scanSensitiveData(options.url));
                break;
            case 'sqlinjection':
                results.push(...await scanSQLInjection(options.url));
                break;
            case 'headers':
                results.push(...await scanInsecureHeaders(options.url));
                break;
            case 'infodisclosure':
                results.push(...await scanInformationDisclosure(options.url));
                break;
            case 'traversal':
                results.push(...await scanDirectoryTraversal(options.url));
                break;
        }
    }

    return results;
} 