import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

interface SecurityCheck {
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  affected_url: string;
  recommendation: string;
  cvss_score: number;
  cwe_id: string;
  owasp_category: string;
}

async function performSecurityScan(url: string): Promise<SecurityCheck[]> {
  const vulnerabilities: SecurityCheck[] = [];
  
  try {
    // Fetch the target URL
    const response = await fetch(url, { 
      redirect: 'follow',
      headers: {
        'User-Agent': 'SecureEval Security Scanner'
      }
    });
    
    const headers = response.headers;
    const html = await response.text();

    // Check for missing security headers
    const securityHeaders = {
      'x-frame-options': 'X-Frame-Options',
      'x-content-type-options': 'X-Content-Type-Options',
      'strict-transport-security': 'Strict-Transport-Security',
      'content-security-policy': 'Content-Security-Policy',
      'x-xss-protection': 'X-XSS-Protection',
    };

    const missingHeaders: string[] = [];
    for (const [key, name] of Object.entries(securityHeaders)) {
      if (!headers.has(key)) {
        missingHeaders.push(name);
      }
    }

    if (missingHeaders.length > 0) {
      vulnerabilities.push({
        type: 'Security Misconfiguration',
        severity: missingHeaders.length > 3 ? 'high' : 'medium',
        title: 'Missing Security Headers',
        description: `The following security headers are missing: ${missingHeaders.join(', ')}. This leaves the application vulnerable to various attacks.`,
        affected_url: url,
        recommendation: 'Implement all recommended security headers to protect against common attacks.',
        cvss_score: missingHeaders.length > 3 ? 6.5 : 4.3,
        cwe_id: 'CWE-16',
        owasp_category: 'A05:2021-Security Misconfiguration',
      });
    }

    // Check for HTTPS
    if (!url.startsWith('https://')) {
      vulnerabilities.push({
        type: 'Insecure Transport',
        severity: 'high',
        title: 'Website Not Using HTTPS',
        description: 'The website is not using HTTPS, which means all data transmitted is sent in plaintext and can be intercepted.',
        affected_url: url,
        recommendation: 'Implement HTTPS with a valid SSL/TLS certificate to encrypt all traffic.',
        cvss_score: 7.4,
        cwe_id: 'CWE-319',
        owasp_category: 'A02:2021-Cryptographic Failures',
      });
    }

    // Check for forms without CSRF protection indicators
    const formMatches = html.match(/<form[^>]*>/gi) || [];
    if (formMatches.length > 0) {
      const hasCSRFToken = html.includes('csrf') || html.includes('_token') || html.includes('authenticity_token');
      if (!hasCSRFToken) {
        vulnerabilities.push({
          type: 'Cross-Site Request Forgery (CSRF)',
          severity: 'medium',
          title: 'Potential CSRF Vulnerability',
          description: `Found ${formMatches.length} form(s) without visible CSRF protection tokens.`,
          affected_url: url,
          recommendation: 'Implement CSRF tokens for all forms that perform state-changing operations.',
          cvss_score: 5.4,
          cwe_id: 'CWE-352',
          owasp_category: 'A01:2021-Broken Access Control',
        });
      }
    }

    // Check for inline JavaScript (potential XSS risk)
    const inlineScriptMatches = html.match(/<script[^>]*>[\s\S]*?<\/script>/gi) || [];
    const onEventMatches = html.match(/on\w+\s*=\s*["'][^"']*["']/gi) || [];
    
    if (inlineScriptMatches.length > 5 || onEventMatches.length > 0) {
      vulnerabilities.push({
        type: 'Cross-Site Scripting (XSS)',
        severity: 'medium',
        title: 'Potential XSS Risk - Inline Scripts Detected',
        description: `Found ${inlineScriptMatches.length} inline script tags and ${onEventMatches.length} inline event handlers. This could indicate XSS vulnerabilities.`,
        affected_url: url,
        recommendation: 'Use Content Security Policy, avoid inline scripts, and properly sanitize all user inputs.',
        cvss_score: 6.1,
        cwe_id: 'CWE-79',
        owasp_category: 'A03:2021-Injection',
      });
    }

    // Check for exposed sensitive information
    const sensitivePatterns = [
      { pattern: /api[_-]?key/i, name: 'API keys' },
      { pattern: /password\s*[:=]/i, name: 'passwords' },
      { pattern: /secret/i, name: 'secrets' },
      { pattern: /token/i, name: 'tokens' },
    ];

    const exposedInfo: string[] = [];
    for (const { pattern, name } of sensitivePatterns) {
      if (pattern.test(html)) {
        exposedInfo.push(name);
      }
    }

    if (exposedInfo.length > 0) {
      vulnerabilities.push({
        type: 'Information Disclosure',
        severity: 'high',
        title: 'Potential Sensitive Information Exposure',
        description: `The page source contains references to: ${exposedInfo.join(', ')}. This could indicate exposed sensitive data.`,
        affected_url: url,
        recommendation: 'Remove all sensitive information from client-side code. Store secrets securely on the server.',
        cvss_score: 7.5,
        cwe_id: 'CWE-200',
        owasp_category: 'A01:2021-Broken Access Control',
      });
    }

    // Check for outdated libraries (basic check)
    const libraryPatterns = [
      { pattern: /jquery[-.]1\./i, name: 'jQuery 1.x', severity: 'medium' as const },
      { pattern: /angular[-.]1\./i, name: 'AngularJS 1.x', severity: 'medium' as const },
      { pattern: /bootstrap[-.]2\./i, name: 'Bootstrap 2.x', severity: 'low' as const },
    ];

    for (const { pattern, name, severity } of libraryPatterns) {
      if (pattern.test(html)) {
        vulnerabilities.push({
          type: 'Using Components with Known Vulnerabilities',
          severity,
          title: `Outdated Library Detected: ${name}`,
          description: `The website appears to be using ${name}, which has known security vulnerabilities.`,
          affected_url: url,
          recommendation: 'Update to the latest stable version of the library or find a more modern alternative.',
          cvss_score: severity === 'medium' ? 5.3 : 3.1,
          cwe_id: 'CWE-1104',
          owasp_category: 'A06:2021-Vulnerable and Outdated Components',
        });
      }
    }

  } catch (error) {
    console.error('Scan error:', error);
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    throw new Error(`Failed to scan URL: ${errorMessage}`);
  }

  return vulnerabilities;
}

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  try {
    const supabaseClient = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_ANON_KEY') ?? '',
      {
        global: {
          headers: { Authorization: req.headers.get('Authorization')! },
        },
      }
    )

    const { scanId, url } = await req.json()

    if (!scanId || !url) {
      throw new Error('scanId and url are required')
    }

    // Update scan status to running
    await supabaseClient
      .from('scans')
      .update({ 
        status: 'running',
        started_at: new Date().toISOString()
      })
      .eq('id', scanId)

    // Perform the security scan
    const vulnerabilities = await performSecurityScan(url)

    // Insert vulnerabilities into database
    if (vulnerabilities.length > 0) {
      const { error: vulnError } = await supabaseClient
        .from('vulnerabilities')
        .insert(
          vulnerabilities.map(v => ({
            scan_id: scanId,
            vulnerability_type: v.type,
            severity: v.severity,
            title: v.title,
            description: v.description,
            affected_url: v.affected_url,
            recommendation: v.recommendation,
            cvss_score: v.cvss_score,
            cwe_id: v.cwe_id,
            owasp_category: v.owasp_category,
          }))
        )

      if (vulnError) throw vulnError
    }

    // Update scan status to completed
    await supabaseClient
      .from('scans')
      .update({ 
        status: 'completed',
        completed_at: new Date().toISOString()
      })
      .eq('id', scanId)

    return new Response(
      JSON.stringify({ 
        success: true, 
        vulnerabilities: vulnerabilities.length,
        message: `Scan completed. Found ${vulnerabilities.length} potential vulnerabilities.`
      }),
      { 
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        status: 200,
      }
    )

  } catch (error) {
    console.error('Error:', error)
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    
    // Try to update scan status to failed
    try {
      const { scanId } = await req.json()
      const supabaseClient = createClient(
        Deno.env.get('SUPABASE_URL') ?? '',
        Deno.env.get('SUPABASE_ANON_KEY') ?? '',
      )
      await supabaseClient
        .from('scans')
        .update({ 
          status: 'failed',
          error_message: errorMessage
        })
        .eq('id', scanId)
    } catch (updateError) {
      console.error('Failed to update scan status:', updateError)
    }

    return new Response(
      JSON.stringify({ error: errorMessage }),
      { 
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        status: 400,
      }
    )
  }
})
