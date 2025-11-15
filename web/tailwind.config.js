/** @type {import('tailwindcss').Config} */
export default {
  // ⬇⬇ THIS is the important part: include ALL your React/JS files,
  // not just ./src (your App.jsx and main.jsx live at the project root).
  content: [
    "./index.html",
    "./**/*.{js,jsx,ts,tsx}",
  ],
  theme: {
    extend: {},
  },
  plugins: [],
};
