/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: '#0b1120',
          card: '#0f172a',
          cardSubtle: '#1e293b',
          border: '#334155',
          cyan: '#06b6d4',
          blue: '#3b82f6',
          confirmed: '#10b981',
          unverified: '#f59e0b',
          critical: '#ef4444',
          high: '#f43f5e',
          medium: '#eab308',
          low: '#64748b',
        }
      },
      fontFamily: {
        sans: ['"Plus Jakarta Sans"', '-apple-system', 'BlinkMacSystemFont', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'monospace'],
      }
    },
  },
  plugins: [],
}
