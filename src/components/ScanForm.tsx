import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Scan, AlertCircle } from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { useAuth } from '@/contexts/AuthContext';
import { toast } from 'sonner';
import { z } from 'zod';

const urlSchema = z.string().url('Please enter a valid URL (e.g., https://example.com)');

export const ScanForm = ({ onScanCreated }: { onScanCreated: () => void }) => {
  const { user } = useAuth();
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    // Validate URL
    try {
      urlSchema.parse(url);
    } catch {
      setError('Please enter a valid URL (e.g., https://example.com)');
      return;
    }

    if (!user) {
      toast.error('You must be logged in to create a scan');
      return;
    }

    setLoading(true);

    try {
      // Create a new scan
      const { data: scan, error: scanError } = await supabase
        .from('scans')
        .insert({
          user_id: user.id,
          target_url: url,
          status: 'pending',
        })
        .select()
        .single();

      if (scanError) throw scanError;

      toast.success('Scan started! This may take a few moments...');

      // Call the edge function to perform actual security scanning
      const { data: session } = await supabase.auth.getSession();
      
      const response = await fetch(
        `${import.meta.env.VITE_SUPABASE_URL}/functions/v1/scan-website`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${session.session?.access_token}`,
          },
          body: JSON.stringify({
            scanId: scan.id,
            url: url,
          }),
        }
      );

      const result = await response.json();

      if (!response.ok) {
        throw new Error(result.error || 'Scan failed');
      }

      toast.success(result.message || 'Scan completed successfully!');
      setUrl('');
      onScanCreated();
    } catch (error: any) {
      toast.error(error.message || 'Failed to create scan');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Scan className="h-5 w-5 text-primary" />
          New Security Scan
        </CardTitle>
        <CardDescription>
          Enter a URL to scan for OWASP Top 10 vulnerabilities
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="url">Target URL</Label>
            <Input
              id="url"
              type="text"
              placeholder="https://example.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              required
            />
            {error && (
              <div className="flex items-center gap-2 text-sm text-destructive">
                <AlertCircle className="h-4 w-4" />
                {error}
              </div>
            )}
          </div>
          <Button type="submit" disabled={loading} className="w-full">
            {loading ? (
              <>
                <Scan className="mr-2 h-4 w-4 animate-spin" />
                Scanning...
              </>
            ) : (
              <>
                <Scan className="mr-2 h-4 w-4" />
                Start Scan
              </>
            )}
          </Button>
        </form>
      </CardContent>
    </Card>
  );
};
