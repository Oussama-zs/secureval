import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { supabase } from '@/integrations/supabase/client';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { ArrowLeft, Download, Shield, AlertTriangle } from 'lucide-react';
import { toast } from 'sonner';
import { format } from 'date-fns';
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';

interface Scan {
  id: string;
  target_url: string;
  status: string;
  created_at: string;
  completed_at: string | null;
  total_vulnerabilities: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
}

interface Vulnerability {
  id: string;
  vulnerability_type: string;
  severity: string;
  title: string;
  description: string;
  affected_url: string | null;
  recommendation: string | null;
  cvss_score: number | null;
  cwe_id: string | null;
  owasp_category: string | null;
}

const ScanDetails = () => {
  const { scanId } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState<Scan | null>(null);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (scanId) {
      fetchScanDetails();
    }
  }, [scanId]);

  const fetchScanDetails = async () => {
    try {
      const { data: scanData, error: scanError } = await supabase
        .from('scans')
        .select('*')
        .eq('id', scanId)
        .single();

      if (scanError) throw scanError;
      setScan(scanData);

      const { data: vulnData, error: vulnError } = await supabase
        .from('vulnerabilities')
        .select('*')
        .eq('scan_id', scanId)
        .order('severity', { ascending: true });

      if (vulnError) throw vulnError;
      setVulnerabilities(vulnData || []);
    } catch (error: any) {
      toast.error(error.message || 'Failed to fetch scan details');
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'bg-destructive text-white';
      case 'high':
        return 'bg-warning text-white';
      case 'medium':
        return 'bg-info text-white';
      case 'low':
        return 'bg-success text-white';
      default:
        return 'bg-secondary';
    }
  };

  const downloadPDF = () => {
    try {
      if (!scan) return;

      const doc = new jsPDF({ unit: 'pt', format: 'a4' });
      const margin = 40;
      let y = margin;

      // Header
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(18);
  doc.text('Secural - Web Security Scan Report', margin, y);
      y += 24;

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(12);
      doc.text(`Target: ${scan.target_url}`, margin, y);
      y += 18;
      doc.text(`Scan date: ${format(new Date(scan.created_at), 'PPpp')}` + (scan.completed_at ? `  •  Completed: ${format(new Date(scan.completed_at), 'PPpp')}` : ''), margin, y);
      y += 24;

      // Summary counters
      const summaryLines = [
        `Total: ${scan.total_vulnerabilities}`,
        `Critical: ${scan.critical_count}`,
        `High: ${scan.high_count}`,
        `Medium: ${scan.medium_count}`,
        `Low: ${scan.low_count}`,
      ];
      doc.text(summaryLines.join('   |   '), margin, y);
      y += 24;

      // Vulnerabilities table
      const columns = [
        { header: 'Title', dataKey: 'title' },
        { header: 'Severity', dataKey: 'severity' },
        { header: 'Type', dataKey: 'vulnerability_type' },
        { header: 'CVSS', dataKey: 'cvss_score' },
        { header: 'CWE', dataKey: 'cwe_id' },
        { header: 'OWASP', dataKey: 'owasp_category' },
      ];

      const rows = vulnerabilities.map(v => ({
        title: v.title || '-',
        severity: (v.severity || '-').toUpperCase(),
        vulnerability_type: v.vulnerability_type || '-',
        cvss_score: v.cvss_score ?? '-',
        cwe_id: v.cwe_id ?? '-',
        owasp_category: v.owasp_category ?? '-',
      }));

      autoTable(doc, {
        startY: y,
        head: [columns.map(c => c.header)],
        body: rows.map(r => columns.map(c => String((r as any)[c.dataKey] ?? '-'))),
        styles: { fontSize: 9, cellPadding: 6, overflow: 'linebreak' },
        headStyles: { fillColor: [28, 28, 30] },
        alternateRowStyles: { fillColor: [245, 245, 245] },
        margin: { left: margin, right: margin },
      });

      let currentY = (doc as any).lastAutoTable?.finalY ?? y;
      currentY += 24;

      // Detailed section (optional): include description and recommendation
      if (vulnerabilities.length) {
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(14);
        if (currentY > doc.internal.pageSize.getHeight() - 120) {
          doc.addPage();
          currentY = margin;
        }
        doc.text('Details', margin, currentY);
        currentY += 16;

        doc.setFont('helvetica', 'normal');
        doc.setFontSize(11);
        vulnerabilities.forEach((v, idx) => {
          const title = `${idx + 1}. ${v.title} [${(v.severity || '').toUpperCase()}]`;
          const details: string[] = [];
          if (v.description) details.push(`Description: ${v.description}`);
          if (v.affected_url) details.push(`Affected URL: ${v.affected_url}`);
          if (v.recommendation) details.push(`Recommendation: ${v.recommendation}`);

          const lines = [title, ...details];
          lines.forEach((line, i) => {
            const wrapped = doc.splitTextToSize(line, doc.internal.pageSize.getWidth() - margin * 2);
            wrapped.forEach(wl => {
              if (currentY > doc.internal.pageSize.getHeight() - margin) {
                doc.addPage();
                currentY = margin;
              }
              doc.text(wl, margin, currentY);
              currentY += 14;
            });
            if (i === lines.length - 1) currentY += 8;
          });
        });
      }

      const urlForName = (() => {
        try {
          const u = new URL(scan.target_url);
          return u.hostname.replace(/[^a-zA-Z0-9.-]/g, '_');
        } catch {
          return scan.target_url.replace(/[^a-zA-Z0-9.-]/g, '_');
        }
      })();
      const ts = format(new Date(scan.created_at), 'yyyyMMdd_HHmm');
  const fileName = `Secural_scan_${urlForName}_${ts}.pdf`;

      doc.save(fileName);
      toast.success('PDF report downloaded');
    } catch (e: any) {
      console.error(e);
      toast.error(e?.message || 'Failed to generate PDF');
    }
  };

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="text-center">
          <Shield className="mx-auto mb-4 h-12 w-12 animate-pulse text-primary" />
          <p className="text-muted-foreground">Loading scan details...</p>
        </div>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Card>
          <CardContent className="flex flex-col items-center py-12">
            <AlertTriangle className="mb-4 h-12 w-12 text-destructive" />
            <p className="mb-4 text-lg">Scan not found</p>
            <Button onClick={() => navigate('/dashboard')}>
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back to Dashboard
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-background to-secondary">
      <header className="border-b border-border/50 bg-card/50 backdrop-blur-sm">
        <div className="container mx-auto flex items-center justify-between px-4 py-4">
          <Button variant="ghost" onClick={() => navigate('/dashboard')}>
            <ArrowLeft className="mr-2 h-4 w-4" />
            Back to Dashboard
          </Button>
          <Button onClick={downloadPDF}>
            <Download className="mr-2 h-4 w-4" />
            Download PDF Report
          </Button>
        </div>
      </header>

      <main className="container mx-auto px-4 py-8">
        <div className="mx-auto max-w-6xl space-y-8">
          <Card>
            <CardHeader>
              <CardTitle className="text-2xl">Scan Report</CardTitle>
              <CardDescription>{scan.target_url}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-4 md:grid-cols-2">
                <div>
                  <p className="text-sm text-muted-foreground">Scan Date</p>
                  <p className="font-medium">{format(new Date(scan.created_at), 'PPpp')}</p>
                </div>
                {scan.completed_at && (
                  <div>
                    <p className="text-sm text-muted-foreground">Completed</p>
                    <p className="font-medium">{format(new Date(scan.completed_at), 'PPpp')}</p>
                  </div>
                )}
              </div>

              <div className="grid gap-4 md:grid-cols-5">
                <div className="rounded-lg border bg-card p-4 text-center">
                  <p className="text-2xl font-bold">{scan.total_vulnerabilities}</p>
                  <p className="text-sm text-muted-foreground">Total</p>
                </div>
                <div className="rounded-lg border border-destructive/20 bg-destructive/10 p-4 text-center">
                  <p className="text-2xl font-bold text-destructive">{scan.critical_count}</p>
                  <p className="text-sm text-muted-foreground">Critical</p>
                </div>
                <div className="rounded-lg border border-warning/20 bg-warning/10 p-4 text-center">
                  <p className="text-2xl font-bold text-warning">{scan.high_count}</p>
                  <p className="text-sm text-muted-foreground">High</p>
                </div>
                <div className="rounded-lg border border-info/20 bg-info/10 p-4 text-center">
                  <p className="text-2xl font-bold text-info">{scan.medium_count}</p>
                  <p className="text-sm text-muted-foreground">Medium</p>
                </div>
                <div className="rounded-lg border border-success/20 bg-success/10 p-4 text-center">
                  <p className="text-2xl font-bold text-success">{scan.low_count}</p>
                  <p className="text-sm text-muted-foreground">Low</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <div>
            <h3 className="mb-4 text-2xl font-semibold">Vulnerabilities Found</h3>
            <div className="space-y-4">
              {vulnerabilities.map((vuln) => (
                <Card key={vuln.id} className="border-l-4" style={{
                  borderLeftColor: vuln.severity === 'critical' ? 'hsl(var(--destructive))' :
                    vuln.severity === 'high' ? 'hsl(var(--warning))' :
                    vuln.severity === 'medium' ? 'hsl(var(--info))' : 'hsl(var(--success))'
                }}>
                  <CardHeader>
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <CardTitle className="text-lg">{vuln.title}</CardTitle>
                        <CardDescription>{vuln.vulnerability_type}</CardDescription>
                      </div>
                      <Badge className={getSeverityColor(vuln.severity)}>
                        {vuln.severity.toUpperCase()}
                      </Badge>
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div>
                      <h4 className="mb-2 font-semibold">Description</h4>
                      <p className="text-sm text-muted-foreground">{vuln.description}</p>
                    </div>

                    {vuln.affected_url && (
                      <div>
                        <h4 className="mb-2 font-semibold">Affected URL</h4>
                        <p className="text-sm text-muted-foreground">{vuln.affected_url}</p>
                      </div>
                    )}

                    {vuln.recommendation && (
                      <div>
                        <h4 className="mb-2 font-semibold">Recommendation</h4>
                        <p className="text-sm text-muted-foreground">{vuln.recommendation}</p>
                      </div>
                    )}

                    <div className="flex gap-4 text-sm">
                      {vuln.cvss_score && (
                        <div>
                          <span className="font-medium">CVSS: </span>
                          <span>{vuln.cvss_score}</span>
                        </div>
                      )}
                      {vuln.cwe_id && (
                        <div>
                          <span className="font-medium">CWE: </span>
                          <span>{vuln.cwe_id}</span>
                        </div>
                      )}
                      {vuln.owasp_category && (
                        <div>
                          <span className="font-medium">OWASP: </span>
                          <span>{vuln.owasp_category}</span>
                        </div>
                      )}
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
};

export default ScanDetails;
