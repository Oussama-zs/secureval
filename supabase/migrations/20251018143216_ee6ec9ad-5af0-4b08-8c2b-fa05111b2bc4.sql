-- Create enum for scan status
CREATE TYPE scan_status AS ENUM ('pending', 'running', 'completed', 'failed');

-- Create enum for vulnerability severity
CREATE TYPE vulnerability_severity AS ENUM ('critical', 'high', 'medium', 'low', 'info');

-- Create scans table
CREATE TABLE public.scans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  target_url TEXT NOT NULL,
  status scan_status NOT NULL DEFAULT 'pending',
  scanner_type TEXT DEFAULT 'comprehensive',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  error_message TEXT,
  total_vulnerabilities INTEGER DEFAULT 0,
  critical_count INTEGER DEFAULT 0,
  high_count INTEGER DEFAULT 0,
  medium_count INTEGER DEFAULT 0,
  low_count INTEGER DEFAULT 0,
  info_count INTEGER DEFAULT 0
);

-- Create vulnerabilities table
CREATE TABLE public.vulnerabilities (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
  vulnerability_type TEXT NOT NULL,
  severity vulnerability_severity NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  affected_url TEXT,
  recommendation TEXT,
  cvss_score NUMERIC(3,1),
  cwe_id TEXT,
  owasp_category TEXT,
  evidence TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Enable RLS
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.vulnerabilities ENABLE ROW LEVEL SECURITY;

-- RLS Policies for scans
CREATE POLICY "Users can view their own scans"
  ON public.scans FOR SELECT
  USING (auth.uid() = user_id);

CREATE POLICY "Users can create their own scans"
  ON public.scans FOR INSERT
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update their own scans"
  ON public.scans FOR UPDATE
  USING (auth.uid() = user_id);

CREATE POLICY "Users can delete their own scans"
  ON public.scans FOR DELETE
  USING (auth.uid() = user_id);

-- RLS Policies for vulnerabilities
CREATE POLICY "Users can view vulnerabilities from their scans"
  ON public.vulnerabilities FOR SELECT
  USING (
    EXISTS (
      SELECT 1 FROM public.scans
      WHERE scans.id = vulnerabilities.scan_id
      AND scans.user_id = auth.uid()
    )
  );

CREATE POLICY "System can create vulnerabilities"
  ON public.vulnerabilities FOR INSERT
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM public.scans
      WHERE scans.id = vulnerabilities.scan_id
      AND scans.user_id = auth.uid()
    )
  );

-- Create indexes for performance
CREATE INDEX idx_scans_user_id ON public.scans(user_id);
CREATE INDEX idx_scans_status ON public.scans(status);
CREATE INDEX idx_scans_created_at ON public.scans(created_at DESC);
CREATE INDEX idx_vulnerabilities_scan_id ON public.vulnerabilities(scan_id);
CREATE INDEX idx_vulnerabilities_severity ON public.vulnerabilities(severity);

-- Create function to update vulnerability counts
CREATE OR REPLACE FUNCTION update_scan_vulnerability_counts()
RETURNS TRIGGER AS $$
BEGIN
  UPDATE public.scans
  SET
    total_vulnerabilities = (
      SELECT COUNT(*) FROM public.vulnerabilities WHERE scan_id = NEW.scan_id
    ),
    critical_count = (
      SELECT COUNT(*) FROM public.vulnerabilities WHERE scan_id = NEW.scan_id AND severity = 'critical'
    ),
    high_count = (
      SELECT COUNT(*) FROM public.vulnerabilities WHERE scan_id = NEW.scan_id AND severity = 'high'
    ),
    medium_count = (
      SELECT COUNT(*) FROM public.vulnerabilities WHERE scan_id = NEW.scan_id AND severity = 'medium'
    ),
    low_count = (
      SELECT COUNT(*) FROM public.vulnerabilities WHERE scan_id = NEW.scan_id AND severity = 'low'
    ),
    info_count = (
      SELECT COUNT(*) FROM public.vulnerabilities WHERE scan_id = NEW.scan_id AND severity = 'info'
    )
  WHERE id = NEW.scan_id;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create trigger to automatically update counts
CREATE TRIGGER update_vulnerability_counts_trigger
AFTER INSERT OR UPDATE OR DELETE ON public.vulnerabilities
FOR EACH ROW
EXECUTE FUNCTION update_scan_vulnerability_counts();