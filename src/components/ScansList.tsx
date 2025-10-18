import { useEffect, useState } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { useAuth } from '@/contexts/AuthContext';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { FileText, ExternalLink, Trash2, AlertTriangle } from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import { toast } from 'sonner';
import { useNavigate } from 'react-router-dom';

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

export const ScansList = ({ refresh }: { refresh: number }) => {
  const { user } = useAuth();
  const navigate = useNavigate();
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (user) {
      fetchScans();
    }
  }, [user, refresh]);

  const fetchScans = async () => {
    try {
      const { data, error } = await supabase
        .from('scans')
        .select('*')
        .order('created_at', { ascending: false });

      if (error) throw error;
      setScans(data || []);
    } catch (error: any) {
      toast.error(error.message || 'Failed to fetch scans');
    } finally {
      setLoading(false);
    }
  };

  const deleteScan = async (scanId: string) => {
    try {
      const { error } = await supabase
        .from('scans')
        .delete()
        .eq('id', scanId);

      if (error) throw error;
      toast.success('Scan deleted successfully');
      fetchScans();
    } catch (error: any) {
      toast.error(error.message || 'Failed to delete scan');
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed':
        return 'bg-success text-white';
      case 'running':
        return 'bg-info text-white';
      case 'failed':
        return 'bg-destructive text-white';
      default:
        return 'bg-warning text-white';
    }
  };

  const getRiskLevel = (scan: Scan) => {
    if (scan.critical_count > 0) return { label: 'Critical', color: 'bg-destructive' };
    if (scan.high_count > 0) return { label: 'High', color: 'bg-warning' };
    if (scan.medium_count > 0) return { label: 'Medium', color: 'bg-info' };
    return { label: 'Low', color: 'bg-success' };
  };

  if (loading) {
    return <div>Loading scans...</div>;
  }

  if (scans.length === 0) {
    return (
      <Card>
        <CardContent className="flex flex-col items-center justify-center py-12">
          <AlertTriangle className="mb-4 h-12 w-12 text-muted-foreground" />
          <p className="text-muted-foreground">No scans yet. Create your first scan above!</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      {scans.map((scan) => {
        const risk = getRiskLevel(scan);
        return (
          <Card key={scan.id} className="transition-shadow hover:shadow-lg">
            <CardHeader>
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <CardTitle className="flex items-center gap-2 text-lg">
                    <ExternalLink className="h-4 w-4 text-primary" />
                    {scan.target_url}
                  </CardTitle>
                  <CardDescription>
                    Scanned {formatDistanceToNow(new Date(scan.created_at), { addSuffix: true })}
                  </CardDescription>
                </div>
                <div className="flex gap-2">
                  <Badge className={getStatusColor(scan.status)}>
                    {scan.status}
                  </Badge>
                  <Badge className={risk.color}>
                    {risk.label}
                  </Badge>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <div className="flex items-center justify-between">
                <div className="flex gap-6 text-sm">
                  <div>
                    <span className="font-medium">Total: </span>
                    <span>{scan.total_vulnerabilities}</span>
                  </div>
                  {scan.critical_count > 0 && (
                    <div>
                      <span className="font-medium text-destructive">Critical: </span>
                      <span>{scan.critical_count}</span>
                    </div>
                  )}
                  {scan.high_count > 0 && (
                    <div>
                      <span className="font-medium text-warning">High: </span>
                      <span>{scan.high_count}</span>
                    </div>
                  )}
                  {scan.medium_count > 0 && (
                    <div>
                      <span className="font-medium text-info">Medium: </span>
                      <span>{scan.medium_count}</span>
                    </div>
                  )}
                  {scan.low_count > 0 && (
                    <div>
                      <span className="font-medium text-success">Low: </span>
                      <span>{scan.low_count}</span>
                    </div>
                  )}
                </div>
                <div className="flex gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => navigate(`/scan/${scan.id}`)}
                  >
                    <FileText className="mr-2 h-4 w-4" />
                    View Details
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => deleteScan(scan.id)}
                  >
                    <Trash2 className="h-4 w-4 text-destructive" />
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
};
