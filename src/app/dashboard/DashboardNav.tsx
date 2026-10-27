'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';

const NAV = [
  { href: '/dashboard', label: "Vue d'ensemble", num: '01' },
  { href: '/dashboard/intents', label: 'Paiements', num: '02' },
  { href: '/dashboard/operators', label: 'Opérateurs', num: '03' },
  { href: '/dashboard/forwarders', label: 'Forwarders', num: '04' },
  { href: '/dashboard/api-keys', label: 'Clés API', num: '05' },
  { href: '/dashboard/webhooks', label: 'Webhooks', num: '06' },
  { href: '/dashboard/developers', label: 'Développeurs', num: '07' },
  { href: '/dashboard/reconciliation', label: 'Réconciliation', num: '08' },
  { href: '/dashboard/settings', label: 'Paramètres', num: '09' },
];

export function DashboardNav() {
  const pathname = usePathname();

  return (
    <nav className="space-y-0.5" aria-label="Navigation principale">
      {NAV.map((item) => {
        const isActive =
          item.href === '/dashboard'
            ? pathname === '/dashboard'
            : pathname.startsWith(item.href);

        return (
          <Link
            key={item.href}
            href={item.href}
            aria-current={isActive ? 'page' : undefined}
            className={`group relative flex items-center gap-3 rounded-sm px-3 py-2.5 text-sm transition-colors duration-200 ${
              isActive
                ? 'bg-[var(--ink)] text-white'
                : 'text-[var(--stone-700)] hover:bg-[var(--stone-100)]'
            }`}
          >
            <span
              className={`font-mono text-[10px] tracking-[0.2em] shrink-0 ${
                isActive ? 'text-[var(--bronze-light)]' : 'text-[var(--stone-400)]'
              }`}
              aria-hidden="true"
            >
              {item.num}
            </span>
            <span className="truncate">{item.label}</span>
          </Link>
        );
      })}
    </nav>
  );
}
