import {
  LayoutDashboard,
  ScrollText,
  ShieldAlert,
  Upload,
  Users,
  type LucideIcon,
} from 'lucide-react';
import type { Permission } from '@/lib/auth/permissions';

export interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  /** Shown only to accounts allowed this; the route itself is guarded the same way. */
  permission?: Permission;
}

export const navItems: readonly NavItem[] = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/events', label: 'Events', icon: ScrollText },
  { to: '/uploads', label: 'Uploads', icon: Upload },
  { to: '/alerts', label: 'Alerts', icon: ShieldAlert },
  { to: '/users', label: 'Users', icon: Users, permission: 'users:manage' },
];
