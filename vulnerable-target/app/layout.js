import "./globals.css";
import Navbar from "./components/Navbar";

export const metadata = {
  title: "Vuln-Shop (intentionally vulnerable demo)",
  description: "Intentionally vulnerable Next.js app for security training/testing only.",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>
        <Navbar />
        <div className="page-shell">{children}</div>
        <p className="footer-note">
          ⚠️ Intentionally vulnerable demo app — educational use only, see README.md
        </p>
      </body>
    </html>
  );
}
