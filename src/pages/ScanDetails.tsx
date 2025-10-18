import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { supabase } from '@/integrations/supabase/client';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { ArrowLeft, Download, Shield, AlertTriangle } from 'lucide-react';
import { toast } from 'sonner';
import { format } from 'date-fns';

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
    // In a real application, you would generate a PDF here
    // For now, we'll just show a message
    toast.info('PDF generation would be implemented here with a library like jsPDF or via an edge function');
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
