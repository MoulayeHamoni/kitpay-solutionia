import { randomBytes } from 'crypto';

// Utilitaires purs (pas de dépendance Supabase) — utilisable côté client et serveur

export function formatMRU(amount: number): string {
  return new Intl.NumberFormat("fr-FR").format(amount) + " MRU";
}

// Server-only (uses Node's crypto). generateRef is called from API routes and
// server actions; if ever imported client-side, move to a server-only module.
export function generateRef(): string {
  let rand = '';
  while (rand.length < 10) {
    rand += randomBytes(8).toString('base64url').replace(/[-_]/g, '').toUpperCase();
  }
  return 'KP-' + rand.slice(0, 10);
}

// Génère un ID slug à partir d'un nom (pour les nouveaux produits)
export function slugify(name: string): string {
  return name
    .toLowerCase()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .substring(0, 50);
}
