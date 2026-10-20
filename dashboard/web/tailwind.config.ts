import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./app/**/*.{js,ts,jsx,tsx}"],
  theme: { extend: { colors: { ink: "#050505", panel: "#111111", line: "#292929", muted: "#a1a1a1", accent: "#f5f5f5" }, boxShadow: { panel: "0 10px 35px rgba(0,0,0,.35)" } } },
  plugins: [],
};

export default config;
