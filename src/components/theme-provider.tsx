"use client";

import { ThemeProvider as NextThemesProvider } from "next-themes";
import type { ThemeProviderProps } from "next-themes";

/**
 * Theme provider wrapper for next-themes.
 *
 * We wrap the app in this provider in layout.tsx so that dark mode
 * works. next-themes stores the user's preference in localStorage and
 * applies the 'dark' class to <html> automatically.
 *
 * attribute="class" — toggles the 'dark' class on <html> (Tailwind's
 *   default dark mode strategy).
 * defaultTheme="system" — respects the user's OS preference on first visit.
 * disableTransitionOnChange — prevents the flash of unstyled content
 *   when switching themes.
 */
export function ThemeProvider({ children, ...props }: ThemeProviderProps) {
  return <NextThemesProvider {...props}>{children}</NextThemesProvider>;
}
