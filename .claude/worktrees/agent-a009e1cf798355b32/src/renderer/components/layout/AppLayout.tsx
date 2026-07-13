import type { ReactNode } from 'react';
import Sidebar from './Sidebar';

export default function AppLayout({ children }: { children: ReactNode }) {
  return (
    <div className="flex h-screen overflow-hidden bg-ink-0 text-t1">
      <Sidebar />
      <main className="flex-1 overflow-auto p-5 min-w-0">{children}</main>
    </div>
  );
}
