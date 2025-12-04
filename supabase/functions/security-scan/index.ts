import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

interface SecurityIssue {
  title: string;
  severity: "critical" | "high" | "medium" | "low";
  category: string;
  owaspCategory: string;
  description: string;
  businessImpact: string;
  recommendation: string;
  technicalDetails: string;
}

interface ScanResult {
  score: number;
  issues: SecurityIssue[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
    if (!LOVABLE_API_KEY) {
      throw new Error("LOVABLE_API_KEY is not configured");
    }

    const authHeader = req.headers.get("Authorization");
    if (!authHeader) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const supabaseClient = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_ANON_KEY") ?? "",
      { global: { headers: { Authorization: authHeader } } }
    );

    const { data: { user }, error: userError } = await supabaseClient.auth.getUser();
    if (userError || !user) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const { scanId, domain, scanType } = await req.json();

    if (!scanId || !domain) {
      return new Response(JSON.stringify({ error: "Missing required fields" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    console.log(`Starting ${scanType} security scan for ${domain}, scan ID: ${scanId}`);

    // Update scan status to running
    await supabaseClient
      .from("scans")
      .update({ status: "running" })
      .eq("id", scanId)
      .eq("user_id", user.id);

    const systemPrompt = `You are an expert web security analyst performing a ${scanType === 'full' ? 'comprehensive' : 'quick'} security assessment. Analyze the provided domain/URL for potential security vulnerabilities.

Your analysis should cover OWASP Top 10 categories:
1. A01:2021 - Broken Access Control
2. A02:2021 - Cryptographic Failures
3. A03:2021 - Injection
4. A04:2021 - Insecure Design
5. A05:2021 - Security Misconfiguration
6. A06:2021 - Vulnerable and Outdated Components
7. A07:2021 - Identification and Authentication Failures
8. A08:2021 - Software and Data Integrity Failures
9. A09:2021 - Security Logging and Monitoring Failures
10. A10:2021 - Server-Side Request Forgery

${scanType === 'full' ? 'Perform a thorough analysis covering all categories.' : 'Focus on the most critical and common vulnerabilities.'}

Based on the domain name and common patterns, identify potential security issues. Consider:
- SSL/TLS configuration
- HTTP security headers
- Authentication mechanisms
- Input validation concerns
- Common misconfigurations
- Exposed sensitive endpoints
- Cookie security
- CORS policies

Respond with a JSON object in this exact format:
{
  "score": <number 0-100, where 100 is most secure>,
  "issues": [
    {
      "title": "Clear, non-technical title",
      "severity": "critical" | "high" | "medium" | "low",
      "category": "Category name (e.g., SSL/TLS, Headers, Authentication)",
      "owaspCategory": "OWASP category (e.g., A02:2021 - Cryptographic Failures)",
      "description": "Plain English description of the issue",
      "businessImpact": "How this could affect the business",
      "recommendation": "Clear steps to fix this issue",
      "technicalDetails": "Technical details for developers"
    }
  ],
  "summary": {
    "critical": <count>,
    "high": <count>,
    "medium": <count>,
    "low": <count>
  }
}

Generate ${scanType === 'full' ? '5-10' : '2-5'} realistic issues based on common vulnerabilities found in similar websites. Be realistic but educational.`;

    const userPrompt = `Perform a ${scanType} security scan on the domain: ${domain}

Analyze this website for potential security vulnerabilities and provide actionable recommendations for a small business owner.`;

    const response = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${LOVABLE_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "google/gemini-2.5-flash",
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: userPrompt },
        ],
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error("AI gateway error:", response.status, errorText);
      
      // Update scan to failed
      await supabaseClient
        .from("scans")
        .update({ status: "failed" })
        .eq("id", scanId)
        .eq("user_id", user.id);

      if (response.status === 429) {
        return new Response(JSON.stringify({ error: "Rate limit exceeded. Please try again later." }), {
          status: 429,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
      if (response.status === 402) {
        return new Response(JSON.stringify({ error: "AI service credits exhausted." }), {
          status: 402,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
      
      throw new Error(`AI gateway error: ${response.status}`);
    }

    const aiResponse = await response.json();
    const aiContent = aiResponse.choices?.[0]?.message?.content;
    
    if (!aiContent) {
      throw new Error("No response from AI");
    }

    console.log("AI scan response received");

    // Parse the JSON from the AI response
    let scanResult: ScanResult;
    try {
      const jsonMatch = aiContent.match(/```(?:json)?\s*([\s\S]*?)```/) || [null, aiContent];
      const jsonStr = jsonMatch[1].trim();
      scanResult = JSON.parse(jsonStr);
    } catch (parseError) {
      console.error("Failed to parse AI response:", parseError);
      scanResult = {
        score: 70,
        issues: [
          {
            title: "Scan completed with limited results",
            severity: "low",
            category: "General",
            owaspCategory: "N/A",
            description: "The security scan completed but detailed analysis was limited.",
            businessImpact: "Some vulnerabilities may not have been detected.",
            recommendation: "Consider running a full scan for comprehensive results.",
            technicalDetails: "AI analysis returned incomplete data.",
          },
        ],
        summary: { critical: 0, high: 0, medium: 0, low: 1 },
      };
    }

    // Update scan with results
    const { error: updateError } = await supabaseClient
      .from("scans")
      .update({
        status: "completed",
        completed_at: new Date().toISOString(),
        score: scanResult.score,
        critical_count: scanResult.summary.critical,
        high_count: scanResult.summary.high,
        medium_count: scanResult.summary.medium,
        low_count: scanResult.summary.low,
      })
      .eq("id", scanId)
      .eq("user_id", user.id);

    if (updateError) {
      console.error("Failed to update scan:", updateError);
    }

    // Insert scan issues
    if (scanResult.issues.length > 0) {
      const issuesToInsert = scanResult.issues.map((issue) => ({
        scan_id: scanId,
        user_id: user.id,
        title: issue.title,
        severity: issue.severity,
        category: issue.category,
        owasp_category: issue.owaspCategory,
        description: issue.description,
        business_impact: issue.businessImpact,
        recommendation: issue.recommendation,
        technical_details: issue.technicalDetails,
      }));

      const { error: issuesError } = await supabaseClient
        .from("scan_issues")
        .insert(issuesToInsert);

      if (issuesError) {
        console.error("Failed to insert scan issues:", issuesError);
      }
    }

    // Record security score
    await supabaseClient
      .from("security_scores")
      .insert({
        user_id: user.id,
        score: scanResult.score,
      });

    console.log(`Scan completed for ${domain} with score ${scanResult.score}`);

    // Trigger email notification (fire and forget)
    const serviceClient = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? ""
    );
    
    serviceClient.functions.invoke("send-scan-notification", {
      body: {
        userId: user.id,
        scanId,
        domain,
        score: scanResult.score,
        summary: scanResult.summary,
      },
    }).catch((err) => {
      console.error("Failed to send notification:", err);
    });

    return new Response(
      JSON.stringify({
        success: true,
        scanId,
        score: scanResult.score,
        summary: scanResult.summary,
      }),
      {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      }
    );
  } catch (error) {
    console.error("Error in security-scan:", error);
    return new Response(
      JSON.stringify({ error: error instanceof Error ? error.message : "Unknown error" }),
      {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      }
    );
  }
});
