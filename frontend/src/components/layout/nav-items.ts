import { LayoutDashboard, ScrollText, ShieldAlert, Upload, type LucideIcon } from 'lucide-react';

export interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
}

export const navItems: readonly NavItem[] = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/events', label: 'Events', icon: ScrollText },
  { to: '/uploads', label: 'Uploads', icon: Upload },
  { to: '/alerts', label: 'Alerts', icon: ShieldAlert },
];
