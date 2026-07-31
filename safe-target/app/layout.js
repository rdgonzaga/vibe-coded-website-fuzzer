export const metadata = {
  title: "Brew & Bytes Cafe",
  description: "Specialty coffee and fresh pastries.",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
