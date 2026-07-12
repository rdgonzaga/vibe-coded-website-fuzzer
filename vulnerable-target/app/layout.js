import "./globals.css";

export const metadata = {
  title: "Vuln-Shop (intentionally vulnerable demo)",
  description: "Intentionally vulnerable Next.js app for security training/testing only.",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
