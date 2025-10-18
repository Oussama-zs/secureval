import { useState } from 'react';
import { useAuth } from '@/contexts/AuthContext';
import { Button } from '@/components/ui/button';
import { Shield, LogOut } from 'lucide-react';
import { ScanForm } from '@/components/ScanForm';
import { ScansList } from '@/components/ScansList';

const Dashboard = () => {
  const { user, signOut } = useAuth();
  const [refreshKey, setRefreshKey] = useState(0);

  const handleScanCreated = () => {
    setRefreshKey(prev => prev + 1);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-background to-secondary">
      <header className="border-b border-border/50 bg-card/50 backdrop-blur-sm">
        <div className="container mx-auto flex items-center justify-between px-4 py-4">
          <div className="flex items-center gap-3">
            <div className="rounded-lg bg-cyber-gradient p-2">
              <Shield className="h-6 w-6 text-white" />
            </div>
            <div>
              <h1 className="text-2xl font-bold">SecureEval</h1>
              <p className="text-sm text-muted-foreground">Web Security Scanner</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <span className="text-sm text-muted-foreground">{user?.email}</span>
            <Button variant="outline" size="sm" onClick={signOut}>
              <LogOut className="mr-2 h-4 w-4" />
              Sign Out
            </Button>
          </div>
        </div>
      </header>

      <main className="container mx-auto px-4 py-8">
        <div className="mx-auto max-w-6xl space-y-8">
          <div>
            <h2 className="mb-2 text-3xl font-bold">Security Dashboard</h2>
            <p className="text-muted-foreground">
              Scan websites for OWASP Top 10 vulnerabilities and generate detailed security reports
            </p>
          </div>

          <ScanForm onScanCreated={handleScanCreated} />

          <div>
            <h3 className="mb-4 text-2xl font-semibold">Recent Scans</h3>
            <ScansList refresh={refreshKey} />
          </div>
        </div>
      </main>
    </div>
  );
};

export default Dashboard;
