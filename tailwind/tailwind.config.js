/**
 * Ahead-of-time Tailwind config for CVE3PO.
 *
 * This mirrors the theme that used to live inline in base.html (the runtime
 * Play CDN `tailwind.config`). The Play CDN generated CSS in the browser via a
 * MutationObserver + JIT, which froze the tab during heavy DOM interaction
 * (Kanban drag & drop). Compiling ahead of time removes that runtime entirely.
 *
 * Colors reference CSS variables (defined in base.html) through the
 * `<alpha-value>` placeholder so opacity modifiers (bg-primary/10, ...) keep
 * working and light/dark still toggles via the `dark` class on <html>.
 */
module.exports = {
  darkMode: "class",
  content: ["../vuln_manager/templates/**/*.html"],
  // Classes assembled dynamically in templates (extensions.html) that the
  // content scanner cannot see literally. Keep in sync with module colors.
  safelist: [
    "bg-primary/10", "bg-secondary/10", "bg-tertiary/10",
    "text-primary", "text-secondary", "text-tertiary",
  ],
  theme: {
    extend: {
      colors: {
        "background": "rgb(var(--md-bg) / <alpha-value>)",
        "surface": "rgb(var(--md-bg) / <alpha-value>)",
        "surface-dim": "rgb(var(--md-bg) / <alpha-value>)",
        "surface-bright": "rgb(var(--md-variant) / <alpha-value>)",
        "surface-variant": "rgb(var(--md-variant) / <alpha-value>)",
        "surface-container-lowest": "rgb(var(--md-lowest) / <alpha-value>)",
        "surface-container-low": "rgb(var(--md-panel-2) / <alpha-value>)",
        "surface-container": "rgb(var(--md-panel) / <alpha-value>)",
        "surface-container-high": "rgb(var(--md-high) / <alpha-value>)",
        "surface-container-highest": "rgb(var(--md-highest) / <alpha-value>)",
        "on-background": "rgb(var(--md-text) / <alpha-value>)",
        "on-surface": "rgb(var(--md-text) / <alpha-value>)",
        "on-surface-variant": "rgb(var(--md-muted) / <alpha-value>)",
        "inverse-surface": "rgb(var(--md-text) / <alpha-value>)",
        "inverse-on-surface": "rgb(var(--md-bg) / <alpha-value>)",
        "outline": "rgb(var(--md-faint) / <alpha-value>)",
        "outline-variant": "rgb(var(--md-line) / <alpha-value>)",
        "primary": "rgb(var(--md-accent) / <alpha-value>)",
        "primary-dim": "rgb(var(--md-accent) / <alpha-value>)",
        "primary-fixed": "rgb(var(--md-accent) / <alpha-value>)",
        "primary-fixed-dim": "rgb(var(--md-accent) / <alpha-value>)",
        "primary-container": "rgb(var(--md-accent-container) / <alpha-value>)",
        "surface-tint": "rgb(var(--md-accent) / <alpha-value>)",
        "inverse-primary": "rgb(var(--md-accent) / <alpha-value>)",
        "on-primary": "rgb(var(--md-on-accent) / <alpha-value>)",
        "on-primary-container": "rgb(var(--md-on-accent) / <alpha-value>)",
        "on-primary-fixed": "rgb(var(--md-on-accent) / <alpha-value>)",
        "on-primary-fixed-variant": "rgb(var(--md-on-accent) / <alpha-value>)",
        "secondary": "rgb(var(--md-muted) / <alpha-value>)",
        "secondary-dim": "rgb(var(--md-muted) / <alpha-value>)",
        "secondary-fixed": "rgb(var(--md-high) / <alpha-value>)",
        "secondary-fixed-dim": "rgb(var(--md-high) / <alpha-value>)",
        "secondary-container": "rgb(var(--md-high) / <alpha-value>)",
        "on-secondary": "rgb(var(--md-text) / <alpha-value>)",
        "on-secondary-container": "rgb(var(--md-text) / <alpha-value>)",
        "on-secondary-fixed": "rgb(var(--md-text) / <alpha-value>)",
        "on-secondary-fixed-variant": "rgb(var(--md-muted) / <alpha-value>)",
        "error": "rgb(var(--md-crit) / <alpha-value>)",
        "error-dim": "rgb(var(--md-crit) / <alpha-value>)",
        "error-container": "rgb(var(--md-crit) / <alpha-value>)",
        "on-error": "rgb(255 255 255 / <alpha-value>)",
        "on-error-container": "rgb(255 255 255 / <alpha-value>)",
        "tertiary": "rgb(var(--md-high-sev) / <alpha-value>)",
        "tertiary-dim": "rgb(var(--md-high-sev) / <alpha-value>)",
        "tertiary-fixed": "rgb(var(--md-high-sev) / <alpha-value>)",
        "tertiary-fixed-dim": "rgb(var(--md-high-sev) / <alpha-value>)",
        "tertiary-container": "rgb(var(--md-high-sev) / <alpha-value>)",
        "on-tertiary": "rgb(255 255 255 / <alpha-value>)",
        "on-tertiary-container": "rgb(255 255 255 / <alpha-value>)",
        "on-tertiary-fixed": "rgb(255 255 255 / <alpha-value>)",
        "on-tertiary-fixed-variant": "rgb(255 255 255 / <alpha-value>)",
      },
      fontFamily: {
        "headline": ["Manrope"],
        "body": ["Inter"],
        "label": ["Inter"],
      },
      borderRadius: {
        "DEFAULT": "0.25rem",
        "lg": "0.3125rem",
        "xl": "0.375rem",
        "2xl": "0.5rem",
        "3xl": "0.625rem",
        "full": "9999px",
      },
    },
  },
  plugins: [
    require("@tailwindcss/forms"),
    require("@tailwindcss/container-queries"),
  ],
};
