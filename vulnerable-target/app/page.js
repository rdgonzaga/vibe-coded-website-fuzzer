// app/page.js
export default function Home() {
  return (
    <main style={{ maxWidth: 480, margin: "80px auto", fontFamily: "sans-serif" }}>
      <h1>⚠️ Vuln-Shop</h1>
      <p>
        A deliberately vulnerable Next.js e-commerce demo for security
        training/testing only. Do not deploy this publicly or reuse this code.
        See <code>README.md</code> for the full list of intentional bugs.
      </p>
      <ul>
        <li><a href="/login">Login</a></li>
        <li><a href="/register">Register</a></li>
        <li><a href="/products">Products (SQL injection demo)</a></li>
        <li><a href="/profile?id=1">Profile (IDOR demo)</a></li>
      </ul>
    </main>
  );
}
